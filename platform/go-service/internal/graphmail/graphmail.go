// Package graphmail sends transactional customer email through Microsoft Graph
// sendMail (PAT-109, PAT-1346), from the noreply mailbox in Patched's own
// Microsoft 365 tenant.
//
// This is the only email transport this service may use for customer mail. The
// legacy internal/notify SMTP/SendGrid path is for internal platform alerts and
// is not extended here: SendGrid is a retired fallback.
//
// Deliberately separate from internal/msgraph. That package is the read-only,
// certificate-authenticated, multi-customer-tenant MDM client, and its own
// documentation states that no per-tenant secret belongs anywhere in it. The
// mailer is the opposite shape: one fixed Patched-owned tenant, a client
// secret, and a write operation. Folding the two together would put a secret
// inside a package that promises it holds none.
//
// Configuration (all four required; any missing one leaves the transport
// unconfigured):
//
//	GRAPH_MAIL_TENANT_ID      Entra tenant id of the Patched.im tenant
//	GRAPH_MAIL_CLIENT_ID      "Patched.im Mailer" app registration id
//	GRAPH_MAIL_CLIENT_SECRET  client secret for that app
//	GRAPH_MAIL_FROM           sending mailbox, e.g. noreply@patched.im
//
// An unconfigured transport fails loudly with ErrNotConfigured on every send.
// It never silently succeeds: a notification that was never sent must read as a
// failed delivery the tenant owner can see, not as a delivered one.
package graphmail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	defaultAuthorityBase = "https://login.microsoftonline.com"
	defaultGraphBaseURL  = "https://graph.microsoft.com/v1.0"
	defaultScope         = "https://graph.microsoft.com/.default"

	// tokenExpirySkew refreshes a cached token this far before its real expiry
	// so a send never starts with a token that expires mid-flight.
	tokenExpirySkew = 2 * time.Minute

	// maxRecipients bounds one sendMail call. Graph itself allows more; this is
	// our own cap so a mis-configured channel cannot turn one finding into a
	// mass mailing.
	maxRecipients = 25
)

// ErrNotConfigured is returned by Send when the Graph mailer credentials are
// absent. Callers must surface this as a delivery failure, not as a no-op.
var ErrNotConfigured = errors.New("graphmail: transport is not configured")

// Message is one outbound email. Bodies are plain text: notification content is
// short, and plain text removes a whole class of HTML injection questions.
type Message struct {
	To      []string
	Subject string
	Body    string
}

// Sender is the behaviour notification delivery depends on. Tests substitute a
// fake; production uses *Client.
type Sender interface {
	Send(ctx context.Context, msg Message) error
	From() string
}

// Client sends mail as one fixed mailbox in one fixed tenant.
type Client struct {
	tenantID     string
	clientID     string
	clientSecret string
	from         string

	// AuthorityBase and GraphBaseURL are overridable so tests can point the
	// client at an httptest server. Production never sets them.
	AuthorityBase string
	GraphBaseURL  string
	HTTPClient    *http.Client

	now func() time.Time

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

// Config carries the four required settings.
type Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	From         string
}

// New builds a Client. It returns ErrNotConfigured when any setting is blank,
// so a partially configured environment cannot produce a client that looks
// usable and fails only at send time.
func New(cfg Config) (*Client, error) {
	cfg.TenantID = strings.TrimSpace(cfg.TenantID)
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.From = strings.TrimSpace(cfg.From)
	if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.From == "" {
		return nil, ErrNotConfigured
	}
	if _, err := mail.ParseAddress(cfg.From); err != nil {
		return nil, fmt.Errorf("graphmail: GRAPH_MAIL_FROM is not a valid address")
	}
	return &Client{
		tenantID:      cfg.TenantID,
		clientID:      cfg.ClientID,
		clientSecret:  cfg.ClientSecret,
		from:          cfg.From,
		AuthorityBase: defaultAuthorityBase,
		GraphBaseURL:  defaultGraphBaseURL,
		HTTPClient:    &http.Client{Timeout: 30 * time.Second},
		now:           time.Now,
	}, nil
}

// FromEnv builds a Client from the GRAPH_MAIL_* environment. It returns
// ErrNotConfigured when the environment does not carry a complete
// configuration; callers log that once at startup and carry on, because an
// operator who has not set up email yet should still get webhook channels.
func FromEnv() (*Client, error) {
	return New(Config{
		TenantID:     os.Getenv("GRAPH_MAIL_TENANT_ID"),
		ClientID:     os.Getenv("GRAPH_MAIL_CLIENT_ID"),
		ClientSecret: os.Getenv("GRAPH_MAIL_CLIENT_SECRET"),
		From:         os.Getenv("GRAPH_MAIL_FROM"),
	})
}

// From reports the sending mailbox.
func (c *Client) From() string { return c.from }

// ValidateRecipients checks an address list before it is stored on a channel,
// so a typo is rejected at configuration time rather than becoming a permanent
// dead-lettered delivery later.
func ValidateRecipients(addresses []string) error {
	if len(addresses) == 0 {
		return errors.New("at least one recipient is required")
	}
	if len(addresses) > maxRecipients {
		return fmt.Errorf("at most %d recipients are allowed", maxRecipients)
	}
	seen := make(map[string]bool, len(addresses))
	for _, a := range addresses {
		a = strings.TrimSpace(a)
		if a == "" {
			return errors.New("recipient address must not be empty")
		}
		parsed, err := mail.ParseAddress(a)
		if err != nil {
			return fmt.Errorf("recipient %q is not a valid email address", a)
		}
		lower := strings.ToLower(parsed.Address)
		if seen[lower] {
			return fmt.Errorf("recipient %q is listed twice", parsed.Address)
		}
		seen[lower] = true
	}
	return nil
}

type sendMailRequest struct {
	Message         sendMailMessage `json:"message"`
	SaveToSentItems bool            `json:"saveToSentItems"`
}

type sendMailMessage struct {
	Subject      string          `json:"subject"`
	Body         sendMailBody    `json:"body"`
	ToRecipients []sendMailToRcp `json:"toRecipients"`
}

type sendMailBody struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

type sendMailToRcp struct {
	EmailAddress struct {
		Address string `json:"address"`
	} `json:"emailAddress"`
}

// Send delivers one message. It returns a non-nil error on any failure; the
// caller decides whether that failure is retriable.
func (c *Client) Send(ctx context.Context, msg Message) error {
	if c == nil {
		return ErrNotConfigured
	}
	if err := ValidateRecipients(msg.To); err != nil {
		return fmt.Errorf("graphmail: %w", err)
	}

	req := sendMailRequest{
		Message: sendMailMessage{
			Subject: msg.Subject,
			Body:    sendMailBody{ContentType: "Text", Content: msg.Body},
		},
		SaveToSentItems: false,
	}
	for _, addr := range msg.To {
		var r sendMailToRcp
		r.EmailAddress.Address = strings.TrimSpace(addr)
		req.Message.ToRecipients = append(req.Message.ToRecipients, r)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("graphmail: marshal sendMail request: %w", err)
	}

	token, err := c.token(ctx)
	if err != nil {
		return err
	}

	endpoint := strings.TrimRight(c.GraphBaseURL, "/") + "/users/" + url.PathEscape(c.from) + "/sendMail"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("graphmail: build sendMail request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return &DeliveryUncertainError{cause: err}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	// Graph answers a successful sendMail with 202 Accepted and no body.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return &SendError{Status: resp.StatusCode, Code: graphErrorCode(respBody)}
}

// DeliveryUncertainError means sendMail did not return a response, so whether
// Graph accepted the message is unknowable. Callers that require at-most-once
// delivery must not retry it. Existing at-least-once callers may deliberately
// retry it and accept the possibility of a duplicate.
type DeliveryUncertainError struct {
	cause error
}

func (e *DeliveryUncertainError) Error() string {
	return "graphmail: sendMail delivery outcome is uncertain"
}

func (e *DeliveryUncertainError) Unwrap() error { return e.cause }

// SendError reports a non-2xx sendMail response. It deliberately carries only
// the status and Graph's own short error code, never the response body and
// never any part of the request, so nothing secret or recipient-identifying
// reaches a log line or a stored delivery error.
type SendError struct {
	Status int
	Code   string
}

func (e *SendError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("graphmail: sendMail returned status %d", e.Status)
	}
	return fmt.Sprintf("graphmail: sendMail returned status %d (%s)", e.Status, e.Code)
}

// Retriable reports whether another attempt could plausibly succeed. Throttling
// and server-side faults are retriable; an authorisation or validation failure
// is not, and retrying it just burns the budget before dead-lettering anyway.
func (e *SendError) Retriable() bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= 500
}

// TokenError reports a failure to acquire a Graph access token.
//
// It is deliberately distinct from SendError. A SendError means Graph rejected
// one message; a TokenError means our own mailer credentials or tenant
// configuration are wrong, which is a different thing for an operator to fix
// and is classified as a configuration fault rather than a per-message one.
//
// It carries the HTTP status, the OAuth error code and, when Entra supplies
// one, the AADSTS code. It never carries the error_description, which echoes
// request detail, and never the request body, which carries the client secret.
type TokenError struct {
	Status int
	Code   string
	AADSTS string
}

func (e *TokenError) Error() string {
	msg := fmt.Sprintf("graphmail: token request rejected with status %d", e.Status)
	if e.Code != "" {
		msg += " (" + e.Code
		if e.AADSTS != "" {
			msg += " " + e.AADSTS
		}
		msg += ")"
	} else if e.AADSTS != "" {
		msg += " (" + e.AADSTS + ")"
	}
	return msg
}

// Retriable reports whether another attempt could plausibly succeed. Throttling
// and server-side faults are; a rejected credential is not, and retrying it
// just spends the budget before dead-lettering anyway.
func (e *TokenError) Retriable() bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= 500
}

// aadstsPattern matches Entra's own error identifier inside error_description.
// Only the identifier is extracted; the surrounding prose is discarded because
// it can echo request detail.
var aadstsPattern = regexp.MustCompile(`AADSTS[0-9]{3,7}`)

// tokenErrorFrom builds a TokenError from a non-200 Entra response, taking only
// the two short identifiers out of the body.
func tokenErrorFrom(status int, body []byte) *TokenError {
	var parsed struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &parsed)

	code := strings.TrimSpace(parsed.Error)
	if len(code) > 64 {
		code = code[:64]
	}
	// The AADSTS code may appear in the description or, on some responses, only
	// in the raw body, so both are searched and nothing else is kept from either.
	aadsts := aadstsPattern.FindString(parsed.ErrorDescription)
	if aadsts == "" {
		aadsts = aadstsPattern.FindString(string(body))
	}
	return &TokenError{Status: status, Code: code, AADSTS: aadsts}
}

// transportCause reduces a transport failure to its underlying cause, dropping
// the *url.Error wrapper because that wrapper carries the request URL.
func transportCause(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		err = urlErr.Err
	}
	msg := strings.TrimSpace(err.Error())
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

func graphErrorCode(body []byte) string {
	var parsed struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ""
	}
	code := strings.TrimSpace(parsed.Error.Code)
	if len(code) > 64 {
		code = code[:64]
	}
	return code
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// token returns a cached access token, refreshing it when it is within
// tokenExpirySkew of expiry.
func (c *Client) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.accessToken != "" && c.now().Add(tokenExpirySkew).Before(c.expiresAt) {
		return c.accessToken, nil
	}

	endpoint := strings.TrimRight(c.AuthorityBase, "/") + "/" + url.PathEscape(c.tenantID) + "/oauth2/v2.0/token"
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("scope", defaultScope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("graphmail: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		// The request URL is dropped and the form body is never touched: the
		// body carries the client secret. What is kept is the underlying
		// transport cause, which is what separates a DNS failure from a
		// timeout from a refused connection for whoever reads the dead letter.
		return "", fmt.Errorf("graphmail: token request failed: %s", transportCause(err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode != http.StatusOK {
		return "", tokenErrorFrom(resp.StatusCode, body)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("graphmail: decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", errors.New("graphmail: token response carried no access_token")
	}

	c.accessToken = tr.AccessToken
	c.expiresAt = c.now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return c.accessToken, nil
}
