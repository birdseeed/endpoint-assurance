// Package feedback owns the durable, tenant-scoped customer feedback queue.
package feedback

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	TypeBug                = "bug"
	TypeFeature            = "feature"
	TypeQuestion           = "question"
	TypeSupport            = "support"
	TypeDesign             = "design"
	CategoryNotWorking     = "not_working"
	CategoryFindings       = "findings_or_reports"
	CategoryAccount        = "account_billing"
	DoorFeedback           = "feedback"
	DoorSupport            = "support"
	SeverityLow            = "low"
	SeverityMedium         = "medium"
	SeverityHigh           = "high"
	SeverityCritical       = "critical"
	maxScreenshotBytes     = 5 * 1024 * 1024
	maxScreenshotPixels    = 12_000_000
	maxRouteCharacters     = 512
	maxBuildCharacters     = 128
	maxUserAgentCharacters = 512
)

var ErrScreenshotTooLarge = errors.New("screenshot exceeds 5MB")
var ErrScreenshotPixelLimit = errors.New("screenshot exceeds pixel limit")

type Submission struct {
	Reference, TenantID, Type, Title, Description, Severity, Category, Route, PortalBuild, TenantDisplaySlug, ReporterRole, BrowserUserAgent, ReporterName, ReporterEmail string
	SubmittedAt                                                                                                                                                           time.Time
	Screenshot                                                                                                                                                            *Screenshot
	ScreenshotAssetURL                                                                                                                                                    string
	ScreenshotUploadFailed                                                                                                                                                bool
}
type Screenshot struct {
	Bytes                 []byte
	ContentType, Filename string
}

func (s Submission) Validate() error {
	if strings.ContainsRune(s.TenantID, '\x00') || strings.ContainsRune(s.ReporterEmail, '\x00') {
		return errors.New("feedback identity must not contain NUL")
	}
	if len([]rune(s.Route)) > maxRouteCharacters || len([]rune(s.PortalBuild)) > maxBuildCharacters || len([]rune(s.BrowserUserAgent)) > maxUserAgentCharacters {
		return errors.New("Feedback context exceeds its character limit.")
	}
	if !validType(s.Type) {
		return errors.New("Feedback type must be feature, design, support, bug or question.")
	}
	if n := len([]rune(s.Title)); n < 5 || n > 120 {
		return errors.New("Title must be between 5 and 120 characters.")
	}
	if n := len([]rune(s.Description)); n == 0 || n > 5000 {
		return errors.New("Description must be between 1 and 5,000 characters.")
	}
	if s.Type == TypeBug {
		if s.Severity != SeverityLow && s.Severity != SeverityMedium && s.Severity != SeverityHigh && s.Severity != SeverityCritical {
			return errors.New("Bug reports need a severity of low, medium, high or critical.")
		}
	} else if s.Severity != "" {
		// PAT-2216: rejected, not ignored. The portal drops a stale severity
		// server-side before forwarding, so only a caller that ignores the
		// contract sends one, and it should learn so plainly.
		return errors.New("Severity applies only to bug reports.")
	}
	// PAT-2347: a support request says what kind of help it needs, and nothing
	// else carries a category. Rejected rather than dropped, as severity is.
	if s.Type == TypeSupport {
		if s.Category != CategoryNotWorking && s.Category != CategoryFindings && s.Category != CategoryAccount {
			return errors.New("Support requests need a category: something is not working, a question about findings or reports, or account and billing.")
		}
	} else if s.Category != "" {
		return errors.New("Category applies only to support requests.")
	}
	return nil
}

func validType(t string) bool {
	switch t {
	case TypeBug, TypeFeature, TypeQuestion, TypeSupport, TypeDesign:
		return true
	}
	return false
}

// Door is the portal area a type belongs to. Support is where something is
// wrong or a question is asked, so the retired Bug and Question types still
// sit behind it; Feedback is a request for something different.
func Door(t string) string {
	switch t {
	case TypeSupport, TypeBug, TypeQuestion:
		return DoorSupport
	}
	return DoorFeedback
}

func doorTypes(door string) []string {
	if door == DoorSupport {
		return []string{TypeSupport, TypeBug, TypeQuestion}
	}
	return []string{TypeFeature, TypeDesign}
}

func limitCharacters(s string, limit int) string {
	runes := []rune(s)
	if len(runes) > limit {
		return string(runes[:limit])
	}
	return s
}

// Capture only the route path, never query/fragment values such as tokens or
// customer search terms. Bounds use characters, matching PostgreSQL checks.
func (s *Submission) SanitizeContext() error {
	u, err := url.Parse(s.Route)
	if err != nil {
		return errors.New("invalid feedback route")
	}
	s.Route = limitCharacters(u.EscapedPath(), maxRouteCharacters)
	s.PortalBuild = limitCharacters(s.PortalBuild, maxBuildCharacters)
	s.BrowserUserAgent = limitCharacters(s.BrowserUserAgent, maxUserAgentCharacters)
	return nil
}
func neutraliseBackticks(s string) string { return strings.ReplaceAll(s, "`", "ˋ") }

// Table context is also untrusted. Flatten whitespace before escaping Markdown
// so headers, routes and browser strings cannot add rows or active markup.
func markdownTableValue(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	var out strings.Builder
	for _, r := range s {
		if strings.ContainsRune("\\|`*_{}[]()#!<>~", r) {
			out.WriteByte('\\')
		}
		out.WriteRune(r)
	}
	return out.String()
}
func BuildLinearIssueBody(s Submission) string {
	screenshot := ""
	if validScreenshotAssetURL(s.ScreenshotAssetURL) {
		screenshot = "\n![Feedback screenshot](<" + s.ScreenshotAssetURL + ">)\n"
	} else if s.ScreenshotUploadFailed {
		screenshot = "\nScreenshot upload failed\n"
	}
	return fmt.Sprintf("<!-- feedback-id: %s -->\n| Field | Value |\n|---|---|\n| Tenant | %s |\n| Type | %s |\n| Severity | %s |\n| Category | %s |\n| Role | %s |\n| Route | %s |\n| Portal build | %s |\n| Browser | %s |\n| Submitted | %s |\n%s\n## Customer text (untrusted)\n```text\nTitle: %s\n\n%s\n```", s.Reference, markdownTableValue(s.TenantDisplaySlug), markdownTableValue(s.Type), markdownTableValue(s.Severity), markdownTableValue(s.Category), markdownTableValue(s.ReporterRole), markdownTableValue(s.Route), markdownTableValue(s.PortalBuild), markdownTableValue(s.BrowserUserAgent), markdownTableValue(s.SubmittedAt.UTC().Format(time.RFC3339)), screenshot, neutraliseBackticks(s.Title), neutraliseBackticks(s.Description))
}

// Reject overflowing chunks atomically and permanently. Fixed capacity keeps
// retained output within the limit even when an encoder retries after failure.
type boundedScreenshotWriter struct {
	data   []byte
	limit  int
	failed bool
}

func newBoundedScreenshotWriter(limit int) *boundedScreenshotWriter {
	return &boundedScreenshotWriter{data: make([]byte, 0, limit), limit: limit}
}

func (w *boundedScreenshotWriter) Write(p []byte) (int, error) {
	if w.failed || len(p) > w.limit-len(w.data) {
		w.failed = true
		return 0, ErrScreenshotTooLarge
	}
	w.data = append(w.data, p...)
	return len(p), nil
}
func SanitizeScreenshot(raw []byte) (*Screenshot, error) {
	if len(raw) > maxScreenshotBytes {
		return nil, ErrScreenshotTooLarge
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode screenshot: %w", err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > maxScreenshotPixels {
		return nil, ErrScreenshotPixelLimit
	}
	if format != "png" && format != "jpeg" {
		return nil, errors.New("screenshot must be PNG or JPEG")
	}
	img, decodedFormat, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode screenshot: %w", err)
	}
	return reencodeScreenshot(img, format, decodedFormat)
}

func reencodeScreenshot(img image.Image, format, decodedFormat string) (*Screenshot, error) {
	if decodedFormat != format {
		return nil, errors.New("screenshot format changed between configuration and full decode")
	}
	out := newBoundedScreenshotWriter(maxScreenshotBytes)
	var err error
	if format == "png" {
		err = png.Encode(out, img)
	} else if format == "jpeg" {
		err = jpeg.Encode(out, img, &jpeg.Options{Quality: 90})
	} else {
		return nil, errors.New("screenshot must be PNG or JPEG")
	}
	if err != nil {
		return nil, err
	}
	ct := "image/png"
	ext := "png"
	if format == "jpeg" {
		ct = "image/jpeg"
		ext = "jpg"
	}
	return &Screenshot{Bytes: out.data, ContentType: ct, Filename: "feedback-screenshot." + ext}, nil
}

type RateWindowCounts struct{ UserLastHour, TenantLastDay int }
type RateLimitReason string

const (
	RateLimitUserHourly  RateLimitReason = "user_hourly"
	RateLimitTenantDaily RateLimitReason = "tenant_daily"
)

type RateDecision struct {
	Allowed bool
	Reason  RateLimitReason
}

func DecideRate(c RateWindowCounts) RateDecision {
	if c.UserLastHour >= 10 {
		return RateDecision{Reason: RateLimitUserHourly}
	}
	if c.TenantLastDay >= 50 {
		return RateDecision{Reason: RateLimitTenantDaily}
	}
	return RateDecision{Allowed: true}
}

type Record struct {
	Submission
	ID                          int64
	Status                      string
	LinearState                 *string
	CreatedAt, LastStatusChange time.Time
}
type Store struct{ Pool *pgxpool.Pool }

func (s Store) Create(ctx context.Context, in Submission) (Record, RateDecision, error) {
	if err := in.SanitizeContext(); err != nil {
		return Record{}, RateDecision{}, err
	}
	if err := in.Validate(); err != nil {
		return Record{}, RateDecision{}, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Record{}, RateDecision{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", in.TenantID+"\\x00"+in.ReporterEmail); err != nil {
		return Record{}, RateDecision{}, err
	}
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", in.TenantID); err != nil {
		return Record{}, RateDecision{}, err
	}
	var c RateWindowCounts
	err = tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE reporter_email=$2 AND created_at>=clock_timestamp()-interval '1 hour'), count(*) FILTER (WHERE created_at>=clock_timestamp()-interval '1 day') FROM feedback WHERE tenant_id=$1::uuid`, in.TenantID, in.ReporterEmail).Scan(&c.UserLastHour, &c.TenantLastDay)
	if err != nil {
		return Record{}, RateDecision{}, err
	}
	d := DecideRate(c)
	if !d.Allowed {
		return Record{}, d, nil
	}
	var r Record
	r.Submission = in
	err = tx.QueryRow(ctx, `INSERT INTO feedback(tenant_id,tenant_display_slug,reporter_email,reporter_role,type,title,description,severity,category,route,portal_build,user_agent,screenshot,screenshot_content_type,screenshot_filename,updated_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,clock_timestamp()) RETURNING id,reference,status,linear_state,created_at,status_changed_at`, in.TenantID, in.TenantDisplaySlug, in.ReporterEmail, in.ReporterRole, in.Type, in.Title, in.Description, nullIfEmpty(in.Severity), nullIfEmpty(in.Category), in.Route, in.PortalBuild, in.BrowserUserAgent, screenBytes(in.Screenshot), screenCT(in.Screenshot), screenName(in.Screenshot)).Scan(&r.ID, &r.Reference, &r.Status, &r.LinearState, &r.CreatedAt, &r.LastStatusChange)
	if err != nil {
		return Record{}, RateDecision{}, err
	}
	if in.Screenshot != nil {
		ext := "png"
		if in.Screenshot.ContentType == "image/jpeg" {
			ext = "jpg"
		}
		r.Screenshot.Filename = r.Reference + "." + ext
		if _, err = tx.Exec(ctx, `UPDATE feedback SET screenshot_filename=$2,updated_at=clock_timestamp() WHERE id=$1`, r.ID, r.Screenshot.Filename); err != nil {
			return Record{}, RateDecision{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return Record{}, RateDecision{}, err
	}
	return r, d, nil
}
func nullIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}
func screenBytes(v *Screenshot) any {
	if v == nil {
		return nil
	}
	return v.Bytes
}
func screenCT(v *Screenshot) any {
	if v == nil {
		return nil
	}
	return v.ContentType
}
func screenName(v *Screenshot) any {
	if v == nil {
		return nil
	}
	return v.Filename
}

type ListItem struct {
	Reference        string    `json:"reference"`
	Type             string    `json:"type"`
	Door             string    `json:"door"`
	Category         *string   `json:"category,omitempty"`
	Title            string    `json:"title"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	LastStatusChange time.Time `json:"last_status_change"`
}

// List returns the tenant's own items, newest first. An empty door returns
// every item, exactly as before PAT-2347; "feedback" or "support" returns only
// that door's types, so the portal shows one list per door.
func (s Store) List(ctx context.Context, tenantID, door string) ([]ListItem, error) {
	var types any
	if door != "" {
		types = doorTypes(door)
	}
	rows, err := s.Pool.Query(ctx, `SELECT reference,type,category,title,status,created_at,status_changed_at FROM feedback WHERE tenant_id=$1::uuid AND ($2::text[] IS NULL OR type = ANY($2::text[])) ORDER BY created_at DESC`, tenantID, types)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ListItem, 0)
	for rows.Next() {
		var x ListItem
		if err := rows.Scan(&x.Reference, &x.Type, &x.Category, &x.Title, &x.Status, &x.CreatedAt, &x.LastStatusChange); err != nil {
			return nil, err
		}
		x.Door = Door(x.Type)
		out = append(out, x)
	}
	return out, rows.Err()
}
