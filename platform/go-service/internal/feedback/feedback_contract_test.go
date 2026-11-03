package feedback

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
	"time"
)

func TestSubmissionValidate(t *testing.T) {
	valid := Submission{
		Reference:   "FB-123",
		Type:        TypeBug,
		Title:       "Device view stops refreshing",
		Description: "Refresh the page after changing the device filter.",
		Severity:    SeverityHigh,
		Route:       "/devices",
		PortalBuild: "portal-2026-09-27",
	}

	for _, tc := range []struct {
		name   string
		change func(*Submission)
		valid  bool
	}{
		{name: "bug with low severity", change: func(s *Submission) { s.Severity = SeverityLow }, valid: true},
		{name: "bug with medium severity", change: func(s *Submission) { s.Severity = SeverityMedium }, valid: true},
		{name: "bug with high severity", valid: true},
		{name: "bug with critical severity", change: func(s *Submission) { s.Severity = SeverityCritical }, valid: true},
		{name: "feature has no severity", change: func(s *Submission) { s.Type, s.Severity = TypeFeature, "" }, valid: true},
		{name: "question has no severity", change: func(s *Submission) { s.Type, s.Severity = TypeQuestion, "" }, valid: true},
		{name: "design has no severity", change: func(s *Submission) { s.Type, s.Severity = TypeDesign, "" }, valid: true},
		{name: "support with not working", change: func(s *Submission) { s.Type, s.Severity, s.Category = TypeSupport, "", CategoryNotWorking }, valid: true},
		{name: "support with findings or reports", change: func(s *Submission) { s.Type, s.Severity, s.Category = TypeSupport, "", CategoryFindings }, valid: true},
		{name: "support with account and billing", change: func(s *Submission) { s.Type, s.Severity, s.Category = TypeSupport, "", CategoryAccount }, valid: true},
		{name: "title has five characters", change: func(s *Submission) { s.Title = strings.Repeat("t", 5) }, valid: true},
		{name: "title has 120 characters", change: func(s *Submission) { s.Title = strings.Repeat("t", 120) }, valid: true},
		{name: "description has 5000 characters", change: func(s *Submission) { s.Description = strings.Repeat("d", 5000) }, valid: true},
		{name: "missing type", change: func(s *Submission) { s.Type = "" }},
		{name: "unknown type", change: func(s *Submission) { s.Type = "other" }},
		{name: "title has four characters", change: func(s *Submission) { s.Title = strings.Repeat("t", 4) }},
		{name: "title has 121 characters", change: func(s *Submission) { s.Title = strings.Repeat("t", 121) }},
		{name: "missing description", change: func(s *Submission) { s.Description = "" }},
		{name: "description has 5001 characters", change: func(s *Submission) { s.Description = strings.Repeat("d", 5001) }},
		{name: "bug needs severity", change: func(s *Submission) { s.Severity = "" }},
		{name: "bug rejects unknown severity", change: func(s *Submission) { s.Severity = "urgent" }},
		{name: "feature rejects severity", change: func(s *Submission) { s.Type = TypeFeature }},
		{name: "question rejects severity", change: func(s *Submission) { s.Type = TypeQuestion }},
		{name: "design rejects severity", change: func(s *Submission) { s.Type = TypeDesign }},
		{name: "support needs a category", change: func(s *Submission) { s.Type, s.Severity = TypeSupport, "" }},
		{name: "support rejects unknown category", change: func(s *Submission) { s.Type, s.Severity, s.Category = TypeSupport, "", "other" }},
		{name: "support rejects severity", change: func(s *Submission) { s.Type, s.Category = TypeSupport, CategoryNotWorking }},
		{name: "feature rejects category", change: func(s *Submission) { s.Type, s.Severity, s.Category = TypeFeature, "", CategoryNotWorking }},
		{name: "bug rejects category", change: func(s *Submission) { s.Category = CategoryNotWorking }},
		{name: "tenant identity rejects NUL", change: func(s *Submission) { s.TenantID = "tenant\x00injection" }},
		{name: "reporter identity rejects NUL", change: func(s *Submission) { s.ReporterEmail = "reporter\x00@example.test" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			submission := valid
			if tc.change != nil {
				tc.change(&submission)
			}
			err := submission.Validate()
			if (err == nil) != tc.valid {
				t.Fatalf("Validate() error = %v, want valid=%t", err, tc.valid)
			}
		})
	}
}

func TestBuildLinearIssueBodyFencesCustomerTextAndOmitsReporterPII(t *testing.T) {
	submission := Submission{
		Reference:         "FB-123",
		Type:              TypeBug,
		Title:             "A title with `inline` markup",
		Description:       "The customer can try to close the fence:\n```markdown\nuntrusted content\n```",
		Severity:          SeverityHigh,
		Route:             "/devices?filter=stale",
		PortalBuild:       "portal-2026-09-27",
		TenantDisplaySlug: "acme-labs",
		ReporterRole:      "viewer",
		BrowserUserAgent:  "Mozilla/5.0 Example Browser",
		SubmittedAt:       time.Date(2026, time.September, 27, 12, 34, 56, 0, time.UTC),
		ReporterName:      "Planted Person",
		ReporterEmail:     "planted.person@example.test",
	}

	body := BuildLinearIssueBody(submission)
	if !strings.Contains(body, "## Customer text (untrusted)\n```text") {
		t.Fatalf("missing explicit untrusted heading: %q", body)
	}
	if !strings.Contains(body, "<!-- feedback-id: FB-123 -->") {
		t.Fatalf("body does not retain the deterministic feedback marker: %q", body)
	}
	if got := strings.Count(body, "```"); got != 2 {
		t.Fatalf("customer text must remain inside one backtick fence; got %d fences in %q", got, body)
	}
	if strings.Contains(body, "```markdown") {
		t.Fatalf("customer backticks were not neutralised: %q", body)
	}
	for _, prohibited := range []string{submission.ReporterName, submission.ReporterEmail, "submitted by"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(prohibited)) {
			t.Errorf("Linear body leaked reporter PII %q: %q", prohibited, body)
		}
	}
	for _, want := range []string{
		submission.TenantDisplaySlug,
		submission.ReporterRole,
		submission.BrowserUserAgent,
		submission.SubmittedAt.Format(time.RFC3339),
		submission.Route,
		submission.PortalBuild,
		string(submission.Type),
		string(submission.Severity),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Linear body does not retain feedback context %q: %q", want, body)
		}
	}
}

func TestSanitizeScreenshotDecodesAndReencodesOnlySupportedImages(t *testing.T) {
	for name, raw := range map[string][]byte{
		"png":  pngWithTrailingBytes(t),
		"jpeg": jpegBytes(t),
	} {
		t.Run(name, func(t *testing.T) {
			clean, err := SanitizeScreenshot(raw)
			if err != nil {
				t.Fatalf("SanitizeScreenshot(%s): %v", name, err)
			}
			if clean.ContentType != "image/png" && clean.ContentType != "image/jpeg" {
				t.Fatalf("unexpected sanitised content type %q", clean.ContentType)
			}
			if bytes.Equal(clean.Bytes, raw) {
				t.Fatal("screenshot was passed through instead of decoded and re-encoded")
			}
			if _, _, err := image.Decode(bytes.NewReader(clean.Bytes)); err != nil {
				t.Fatalf("sanitised screenshot is not a decodable image: %v", err)
			}
		})
	}

	if _, err := SanitizeScreenshot([]byte("not an image")); err == nil {
		t.Fatal("non-image screenshot accepted")
	}
}

func TestSanitizeScreenshotEnforcesByteAndPixelBoundsBeforeDecode(t *testing.T) {
	tooLarge := bytes.Repeat([]byte{'x'}, 5*1024*1024+1)
	if _, err := SanitizeScreenshot(tooLarge); !errors.Is(err, ErrScreenshotTooLarge) {
		t.Fatalf("oversized screenshot error = %v, want ErrScreenshotTooLarge", err)
	}

	if _, err := SanitizeScreenshot(pngHeader(50_000, 50_000)); !errors.Is(err, ErrScreenshotPixelLimit) {
		t.Fatalf("oversized-pixel screenshot error = %v, want ErrScreenshotPixelLimit", err)
	}
	if _, err := SanitizeScreenshot(pngHeader(4000, 3001)); !errors.Is(err, ErrScreenshotPixelLimit) {
		t.Fatalf("12MP overflow error = %v", err)
	}
	if _, err := SanitizeScreenshot(pngHeader(4000, 3000)); errors.Is(err, ErrScreenshotPixelLimit) || err == nil {
		t.Fatalf("12MP boundary should pass dimensions then fail incomplete decode: %v", err)
	}
}

func TestBuildLinearIssueBodyEscapesAllContextValues(t *testing.T) {
	attack := "cell|injected\r\n| Forged | row |\u2028``` [link](https://example.test) <b>bold</b>\\"
	s := Submission{Reference: "FB-123", TenantDisplaySlug: attack, Type: attack, Severity: attack, ReporterRole: attack, Route: attack, PortalBuild: attack, BrowserUserAgent: attack}
	body := BuildLinearIssueBody(s)
	if strings.Count(body, "```") != 2 || strings.Count(body, "<!-- feedback-id:") != 1 {
		t.Fatalf("context escaped its boundary: %q", body)
	}
	for _, label := range []string{"Tenant", "Type", "Severity", "Role", "Route", "Portal build", "Browser"} {
		want := "| " + label + " | cell\\|injected \\| Forged \\| row \\| \\`\\`\\` \\[link\\]\\(https://example.test\\) \\<b\\>bold\\</b\\>\\\\ |"
		if !strings.Contains(body, want) {
			t.Errorf("missing escaped %s cell in %q", label, body)
		}
	}
	if strings.Contains(body, "\n| Forged") {
		t.Fatalf("injected row: %q", body)
	}
}

func TestScreenshotEncoderOutputIsBounded(t *testing.T) {
	// Exercise the real PNG encoder on incompressible pixels with a small output
	// budget, without generating a multi-megabyte fixture for every test run.
	img := image.NewRGBA(image.Rect(0, 0, 128, 128))
	var seed uint32 = 1
	for i := range img.Pix {
		seed = seed*1664525 + 1013904223
		img.Pix[i] = byte(seed >> 24)
	}
	out := newBoundedScreenshotWriter(128)
	if err := png.Encode(out, img); !errors.Is(err, ErrScreenshotTooLarge) {
		t.Fatalf("encoder overflow error = %v", err)
	}
	if len(out.data) > 128 || cap(out.data) != 128 {
		t.Fatalf("unbounded encoder buffer: len=%d cap=%d", len(out.data), cap(out.data))
	}
	if n, err := out.Write([]byte("more")); n != 0 || !errors.Is(err, ErrScreenshotTooLarge) || len(out.data) > 128 {
		t.Fatalf("overflow writer resumed: %v, len=%d", err, len(out.data))
	}
	boundary := newBoundedScreenshotWriter(3)
	if n, err := boundary.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatalf("exact bound write: %d %v", n, err)
	}
	if n, err := boundary.Write([]byte("de")); n != 0 || !errors.Is(err, ErrScreenshotTooLarge) || string(boundary.data) != "abc" {
		t.Fatalf("atomic bound write: %d %v", n, err)
	}
	atomic := newBoundedScreenshotWriter(4)
	if _, err := atomic.Write([]byte("ab")); err != nil {
		t.Fatal(err)
	}
	if n, err := atomic.Write([]byte("cde")); n != 0 || !errors.Is(err, ErrScreenshotTooLarge) || string(atomic.data) != "ab" {
		t.Fatalf("overflow partly written: %d/%v/%q", n, err, atomic.data)
	}
	for _, chunk := range [][]byte{[]byte("c"), nil} {
		if n, err := atomic.Write(chunk); n != 0 || !errors.Is(err, ErrScreenshotTooLarge) || string(atomic.data) != "ab" {
			t.Fatalf("failed writer resumed: %d/%v/%q", n, err, atomic.data)
		}
	}
}

func TestScreenshotFormatMismatchRejectedBeforeReencoding(t *testing.T) {
	// A nil image would panic if passed to an encoder, proving the format guard
	// executes before re-encoding without modifying the global image registry.
	if _, err := reencodeScreenshot(nil, "png", "jpeg"); err == nil || !strings.Contains(err.Error(), "format changed") {
		t.Fatalf("format mismatch accepted:%v", err)
	}
}

func TestFeedbackStoreRejectsNULIdentityBeforeSQL(t *testing.T) {
	for _, in := range []Submission{{TenantID: "bad\x00tenant"}, {ReporterEmail: "bad\x00email"}} {
		if _, _, err := (Store{}).Create(context.Background(), in); err == nil || !strings.Contains(err.Error(), "NUL") {
			t.Fatalf("identity reached nil SQL pool:%v", err)
		}
	}
}

func TestDecideRate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		counts  RateWindowCounts
		allowed bool
		reason  RateLimitReason
	}{
		{name: "within both budgets", counts: RateWindowCounts{UserLastHour: 9, TenantLastDay: 49}, allowed: true},
		{name: "tenth user submission is allowed", counts: RateWindowCounts{UserLastHour: 9, TenantLastDay: 0}, allowed: true},
		{name: "eleventh user submission is refused", counts: RateWindowCounts{UserLastHour: 10, TenantLastDay: 0}, reason: RateLimitUserHourly},
		{name: "fiftieth tenant submission is allowed", counts: RateWindowCounts{UserLastHour: 0, TenantLastDay: 49}, allowed: true},
		{name: "fifty-first tenant submission is refused", counts: RateWindowCounts{UserLastHour: 0, TenantLastDay: 50}, reason: RateLimitTenantDaily},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decision := DecideRate(tc.counts)
			if decision.Allowed != tc.allowed {
				t.Fatalf("allowed = %v, want %v (%+v)", decision.Allowed, tc.allowed, decision)
			}
			if decision.Reason != tc.reason {
				t.Fatalf("reason = %q, want %q", decision.Reason, tc.reason)
			}
		})
	}
}

func pngWithTrailingBytes(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatal(err)
	}
	return append(b.Bytes(), []byte("untrusted trailing bytes")...)
}

func jpegBytes(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, &jpeg.Options{Quality: 25}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// pngHeader is sufficient for image.DecodeConfig to inspect dimensions. Its
// deliberately impossible size proves that production code checks dimensions
// before allocating pixels or attempting a full decode.
func pngHeader(width, height uint32) []byte {
	const (
		pngSignature = "\x89PNG\r\n\x1a\n"
		ihdr         = "IHDR"
	)
	chunk := make([]byte, 4+4+13+4)
	binary.BigEndian.PutUint32(chunk[0:4], 13)
	copy(chunk[4:8], ihdr)
	binary.BigEndian.PutUint32(chunk[8:12], width)
	binary.BigEndian.PutUint32(chunk[12:16], height)
	chunk[16] = 8 // bit depth
	chunk[17] = 2 // true colour
	binary.BigEndian.PutUint32(chunk[21:25], crc32.ChecksumIEEE(chunk[4:21]))
	return append([]byte(pngSignature), chunk...)
}

func TestDoorGroupsTypesBySupportAndFeedback(t *testing.T) {
	for typ, want := range map[string]string{
		TypeSupport:  DoorSupport,
		TypeBug:      DoorSupport,
		TypeQuestion: DoorSupport,
		TypeFeature:  DoorFeedback,
		TypeDesign:   DoorFeedback,
	} {
		if got := Door(typ); got != want {
			t.Errorf("Door(%q) = %q, want %q", typ, got, want)
		}
	}
	for _, door := range []string{DoorSupport, DoorFeedback} {
		for _, typ := range doorTypes(door) {
			if Door(typ) != door {
				t.Errorf("doorTypes(%q) lists %q, which belongs to %q", door, typ, Door(typ))
			}
		}
	}
}

func TestBuildLinearIssueBodyCarriesSupportCategory(t *testing.T) {
	body := BuildLinearIssueBody(Submission{Reference: "FB-9", Type: TypeSupport, Category: CategoryFindings, Title: "Report is empty", Description: "x", SubmittedAt: time.Now()})
	if !strings.Contains(body, "| Type | support |") || !strings.Contains(body, "| Category | findings\\_or\\_reports |") {
		t.Fatalf("support type and category must be in the issue body table: %s", body)
	}
}
