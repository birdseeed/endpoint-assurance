// Package notify provides a best-effort multi-channel notification dispatcher
// for platform events (PAT-117). Channels are best-effort and independent —
// a failing channel logs and does not block the caller.
//
// Configured via environment variables; absent vars disable the channel silently.
//
//	NOTIFY_SLACK_WEBHOOK_URL   Slack incoming-webhook URL
//	NOTIFY_SMTP_HOST           SMTP host (e.g. smtp.sendgrid.net)
//	NOTIFY_SMTP_PORT           SMTP port (default 587)
//	NOTIFY_SMTP_USER           SMTP username
//	NOTIFY_SMTP_PASS           SMTP password
//	NOTIFY_SMTP_FROM           From address
//	NOTIFY_SMTP_TO             Recipient address (comma-separated for multiple)
//	DASHBOARD_BASE_URL         Dashboard base URL for links back to the tenant
//	                           Software Catalogue (default https://dashboard.patched.im)
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// EventKind identifies the type of notification event.
type EventKind string

const (
	KindRolloutAutoPaused   EventKind = "rollout_auto_paused"
	KindAppLaunchRestricted EventKind = "app_launch_restricted"
	KindNewAppDetected      EventKind = "new_app_detected"
)

// Event carries the notification payload.
type Event struct {
	TenantID string
	Kind     EventKind
	Label    string
	Version  string
	Reason   string

	// Fields used by KindAppLaunchRestricted (PAT-820).
	Actor        string    // operator who made the change, when known
	Platform     string    // macos|windows|any, when known
	SourceAction string    // e.g. "allowlist_launch_restricted", "app_policy_unapproved"
	HostCount    *int      // affected host count, nil when not known
	Link         string    // link back to the tenant Software Catalogue, "" to omit
	Timestamp    time.Time // event time; defaults to now() if zero

	// Fields used by KindNewAppDetected (PAT-819).
	PublisherSignature string    // team_id/signer or bundle identifier, when known
	SuggestedAction    string    // "approve" | "defer", from the catalog join at detection time
	FirstSeen          time.Time // when the app first appeared in the tenant's estate
}

// Notifier dispatches events to configured channels.
type Notifier struct {
	slackURL string
	smtpHost string
	smtpPort int
	smtpUser string
	smtpPass string
	smtpFrom string
	smtpTo   []string
}

// New reads configuration from environment variables and returns a Notifier.
// Channels with missing config are silently disabled.
func New() *Notifier {
	port := 587
	if p := os.Getenv("NOTIFY_SMTP_PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	var smtpTo []string
	if v := os.Getenv("NOTIFY_SMTP_TO"); v != "" {
		for _, addr := range strings.Split(v, ",") {
			addr = strings.TrimSpace(addr)
			if addr != "" {
				smtpTo = append(smtpTo, addr)
			}
		}
	}
	return &Notifier{
		slackURL: os.Getenv("NOTIFY_SLACK_WEBHOOK_URL"),
		smtpHost: os.Getenv("NOTIFY_SMTP_HOST"),
		smtpPort: port,
		smtpUser: os.Getenv("NOTIFY_SMTP_USER"),
		smtpPass: os.Getenv("NOTIFY_SMTP_PASS"),
		smtpFrom: os.Getenv("NOTIFY_SMTP_FROM"),
		smtpTo:   smtpTo,
	}
}

// Enabled reports whether any channel is configured. Callers can use this to
// skip building an Event (e.g. an expensive best-effort field lookup) when
// nothing would ever be delivered — safe on a nil Notifier.
func (n *Notifier) Enabled() bool {
	return n != nil && (n.slackURL != "" || (n.smtpHost != "" && len(n.smtpTo) > 0))
}

// ConfiguredChannelCount reports how many notification channels have their
// env vars set (0, 1, or 2 — slack and email are independent). PAT-1215:
// Dispatch silently no-ops a channel whose config is absent (by design —
// see the package doc and TestDispatchMissingSlackConfigDoesNotCallOut),
// which means a fully-unconfigured Notifier looks identical to a healthy one
// from outside; app-restriction and new-app-detected alerts can go dark with
// zero external symptom. This method exists so a caller (the /admin/health
// surface) can report the count and make "zero channels configured"
// distinguishable from "channels configured and working" — visibility only,
// it does not change Dispatch's silent-skip behaviour. Safe on a nil
// Notifier, matching Enabled() above.
func (n *Notifier) ConfiguredChannelCount() int {
	if n == nil {
		return 0
	}
	count := 0
	if n.slackURL != "" {
		count++
	}
	if n.smtpHost != "" && len(n.smtpTo) > 0 {
		count++
	}
	return count
}

// Dispatch fans out the event to all configured channels. Non-blocking.
func (n *Notifier) Dispatch(ctx context.Context, e Event) {
	if n == nil {
		return
	}
	go func() {
		if n.slackURL != "" {
			if err := n.sendSlack(e); err != nil {
				slog.Warn("notify: slack failed", "kind", e.Kind, "tenant_id", e.TenantID, "err", err)
			}
		}
		if n.smtpHost != "" && len(n.smtpTo) > 0 {
			if err := n.sendEmail(e); err != nil {
				slog.Warn("notify: email failed", "kind", e.Kind, "tenant_id", e.TenantID, "err", err)
			}
		}
	}()
}

func (n *Notifier) sendSlack(e Event) error {
	msg := buildSlackMessage(e)
	payload, err := json.Marshal(map[string]string{"text": msg})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.slackURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack webhook returned %d", resp.StatusCode)
	}
	return nil
}

func (n *Notifier) sendEmail(e Event) error {
	subject := buildEmailSubject(e)
	body := buildSlackMessage(e)
	msg := []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		n.smtpFrom,
		strings.Join(n.smtpTo, ", "),
		subject,
		body,
	))
	addr := fmt.Sprintf("%s:%d", n.smtpHost, n.smtpPort)
	var auth smtp.Auth
	if n.smtpUser != "" {
		auth = smtp.PlainAuth("", n.smtpUser, n.smtpPass, n.smtpHost)
	}
	return smtp.SendMail(addr, auth, n.smtpFrom, n.smtpTo, msg)
}

func buildSlackMessage(e Event) string {
	switch e.Kind {
	case KindRolloutAutoPaused:
		return fmt.Sprintf(
			"⚠️ Patched — rollout auto-paused\nTenant: %s\nApp: %s v%s\nReason: %s",
			e.TenantID, e.Label, e.Version, e.Reason,
		)
	case KindAppLaunchRestricted:
		return buildAppLaunchRestrictedMessage(e)
	case KindNewAppDetected:
		return buildNewAppDetectedMessage(e)
	default:
		return fmt.Sprintf("Patched notification: %s (tenant %s)", e.Kind, e.TenantID)
	}
}

func buildAppLaunchRestrictedMessage(e Event) string {
	ts := e.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	platform := e.Platform
	if platform == "" {
		platform = "unknown"
	}
	actor := e.Actor
	if actor == "" {
		actor = "unknown"
	}
	hosts := "unknown"
	if e.HostCount != nil {
		hosts = strconv.Itoa(*e.HostCount)
	}
	msg := fmt.Sprintf(
		"🚫 Patched — app launch restricted\nTenant: %s\nApp: %s\nPlatform: %s\nAction: %s\nActor: %s\nHosts affected: %s\nTime: %s",
		e.TenantID, e.Label, platform, e.SourceAction, actor, hosts, ts.Format(time.RFC3339),
	)
	if e.Link != "" {
		msg += fmt.Sprintf("\nSoftware Catalogue: %s", e.Link)
	}
	return msg
}

func buildNewAppDetectedMessage(e Event) string {
	ts := e.FirstSeen
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	platform := e.Platform
	if platform == "" {
		platform = "unknown"
	}
	publisher := e.PublisherSignature
	if publisher == "" {
		publisher = "unknown"
	}
	hosts := "unknown"
	if e.HostCount != nil {
		hosts = strconv.Itoa(*e.HostCount)
	}
	suggested := e.SuggestedAction
	if suggested == "" {
		suggested = "unknown"
	}
	msg := fmt.Sprintf(
		"🆕 Patched — new app detected\nTenant: %s\nApp: %s\nPlatform: %s\nPublisher/signature: %s\nHosts: %s\nFirst seen: %s\nSuggested action: %s",
		e.TenantID, e.Label, platform, publisher, hosts, ts.Format(time.RFC3339), suggested,
	)
	if e.Link != "" {
		msg += fmt.Sprintf("\nSoftware Catalogue (New): %s", e.Link)
	}
	return msg
}

func buildEmailSubject(e Event) string {
	switch e.Kind {
	case KindRolloutAutoPaused:
		return fmt.Sprintf("[Patched] Rollout auto-paused: %s v%s", e.Label, e.Version)
	case KindAppLaunchRestricted:
		return fmt.Sprintf("[Patched] App launch restricted: %s", e.Label)
	case KindNewAppDetected:
		return fmt.Sprintf("[Patched] New app detected: %s", e.Label)
	default:
		return fmt.Sprintf("[Patched] %s", e.Kind)
	}
}

// CatalogueLink builds a dashboard link back to the tenant's Software
// Catalogue. Configurable via DASHBOARD_BASE_URL env var; defaults to the
// production dashboard.
func CatalogueLink(tenantID string) string {
	base := os.Getenv("DASHBOARD_BASE_URL")
	if base == "" {
		base = "https://dashboard.patched.im"
	}
	return strings.TrimRight(base, "/") + "/tenants/" + tenantID + "/catalogue"
}

// NewAppsCatalogueLink builds a dashboard link back to the tenant's Software
// Catalogue, pre-filtered to the New-app triage queue (PAT-819).
func NewAppsCatalogueLink(tenantID string) string {
	return CatalogueLink(tenantID) + "?status=new"
}
