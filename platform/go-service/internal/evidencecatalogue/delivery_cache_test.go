package evidencecatalogue

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWindowsDeliveryCacheConcurrentAdmissionAndHandlerIsolation(t *testing.T) {
	var publications, checks atomic.Int32
	newPublisher := func() *WindowsDeliveryPublisher {
		return &WindowsDeliveryPublisher{
			publish: func(context.Context, time.Time) (*WindowsDelivery, error) {
				publications.Add(1)
				return EmbeddedWindowsDelivery()
			},
			check: func(context.Context, *WindowsDelivery) error { checks.Add(1); return nil },
		}
	}
	publisher := newPublisher()
	const requests = 32
	var wg sync.WaitGroup
	errs := make(chan error, requests)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			delivery, err := publisher.Delivery(context.Background(), deliveryTestNow())
			if err == nil {
				// Each caller owns its returned copy. Mutating it must neither
				// race with another request nor poison the admitted publication.
				delivery.DeliveryVersion = 999
				delivery.Targets = append(delivery.Targets, validDeliveryTarget())
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if publications.Load() != 1 || checks.Load() != requests-1 {
		t.Fatalf("publications=%d head checks=%d", publications.Load(), checks.Load())
	}
	delivery, err := publisher.Delivery(context.Background(), deliveryTestNow())
	if err != nil || delivery.DeliveryVersion != 1 || len(delivery.Targets) != 0 {
		t.Fatalf("response mutation leaked into cache: %+v, %v", delivery, err)
	}
	if _, err := newPublisher().Delivery(context.Background(), deliveryTestNow()); err != nil {
		t.Fatal(err)
	}
	if publications.Load() != 2 {
		t.Fatal("separate handler reused another handler's admission")
	}
}

func TestWindowsDeliveryCacheRetriesTransientAdmissionAndHeadErrors(t *testing.T) {
	publications, checks := 0, 0
	publisher := &WindowsDeliveryPublisher{
		publish: func(context.Context, time.Time) (*WindowsDelivery, error) {
			publications++
			if publications == 1 {
				return nil, errors.New("temporary admission failure")
			}
			return EmbeddedWindowsDelivery()
		},
		check: func(context.Context, *WindowsDelivery) error {
			checks++
			if checks == 1 {
				return errors.New("temporary head read failure")
			}
			return nil
		},
	}
	for i, wantError := range []bool{true, false, true, false} {
		delivery, err := publisher.Delivery(context.Background(), deliveryTestNow())
		if (err != nil) != wantError || (wantError && delivery != nil) {
			t.Fatalf("request %d: delivery=%+v err=%v", i, delivery, err)
		}
	}
	if publications != 2 || checks != 2 {
		t.Fatalf("publications=%d head checks=%d", publications, checks)
	}
}

func TestWindowsDeliveryCacheRevalidatesExpiryWithoutRenewal(t *testing.T) {
	publications, checks := 0, 0
	publisher := &WindowsDeliveryPublisher{
		publish: func(context.Context, time.Time) (*WindowsDelivery, error) {
			publications++
			return EmbeddedWindowsDelivery()
		},
		check: func(context.Context, *WindowsDelivery) error { checks++; return nil },
	}
	delivery, err := publisher.Delivery(context.Background(), deliveryTestNow())
	if err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339, delivery.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Delivery(context.Background(), expires.Add(-time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{expires, expires.Add(time.Hour)} {
		if delivery, err := publisher.Delivery(context.Background(), now); err == nil || delivery != nil {
			t.Fatal("expired cached publication served")
		}
	}
	if publications != 1 || checks != 1 {
		t.Fatalf("expired publication was refreshed or checked in DB: publish=%d check=%d", publications, checks)
	}
}

func TestWindowsDeliveryCacheDoesNotRememberInvalidAdmission(t *testing.T) {
	calls := 0
	publisher := &WindowsDeliveryPublisher{
		publish: func(context.Context, time.Time) (*WindowsDelivery, error) {
			calls++
			d, err := EmbeddedWindowsDelivery()
			if calls == 1 {
				d.ContentHash = "invalid"
			}
			return d, err
		},
		check: func(context.Context, *WindowsDelivery) error { return nil },
	}
	if _, err := publisher.Delivery(context.Background(), deliveryTestNow()); err == nil {
		t.Fatal("invalid admission accepted")
	}
	if _, err := publisher.Delivery(context.Background(), deliveryTestNow()); err != nil {
		t.Fatal("valid retry poisoned", err)
	}
	if calls != 2 {
		t.Fatalf("admission attempts=%d", calls)
	}
}
