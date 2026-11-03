package msgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultAuthorityBase = "https://login.microsoftonline.com"
	defaultGraphScope    = "https://graph.microsoft.com/.default"
	grantTypeClientCreds = "client_credentials"
	assertionType        = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// expirySkew refreshes a cached token this long before its real expiry,
	// so a request never starts with a token that expires mid-flight.
	expirySkew = 2 * time.Minute
)

// TokenSource acquires and caches Graph access tokens per tenant, using one
// shared certificate for every tenant it is asked about. It is safe for
// concurrent use: tokens for different tenants are fetched and refreshed
// independently, with no shared mutable state between them beyond the
// certificate and client id, which are read-only after construction.
type TokenSource struct {
	ClientID      string
	Cert          *Certificate
	HTTPClient    *http.Client
	AuthorityBase string // overridable for tests; defaults to defaultAuthorityBase
	Scope         string // overridable for tests; defaults to defaultGraphScope

	now func() time.Time

	mu      sync.Mutex // guards entries map membership only, never a refresh itself
	entries map[string]*tenantTokenEntry
}

type tenantTokenEntry struct {
	mu          sync.Mutex // serializes refreshes for this one tenant
	accessToken string
	expiresAt   time.Time
}

// NewTokenSource builds a TokenSource for a single Entra app registration
// authenticated with cert. clientID is the app (client) id shared by every
// tenant.
func NewTokenSource(clientID string, cert *Certificate) *TokenSource {
	return &TokenSource{
		ClientID:      clientID,
		Cert:          cert,
		HTTPClient:    &http.Client{Timeout: 30 * time.Second},
		AuthorityBase: defaultAuthorityBase,
		Scope:         defaultGraphScope,
		now:           time.Now,
		entries:       make(map[string]*tenantTokenEntry),
	}
}

// Token returns a usable bearer token for tenantID, serving from cache when
// the cached token is not within expirySkew of expiring, otherwise
// acquiring a fresh one from Entra. Adding a second tenant needs no change
// here: this is keyed purely by the tenantID argument the caller passes.
func (ts *TokenSource) Token(ctx context.Context, tenantID string) (string, error) {
	if err := validateTenantID(tenantID); err != nil {
		return "", err
	}

	entry := ts.entryFor(tenantID)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.accessToken != "" && ts.now().Add(expirySkew).Before(entry.expiresAt) {
		return entry.accessToken, nil
	}

	token, expiresIn, err := ts.fetchToken(ctx, tenantID)
	if err != nil {
		return "", err
	}
	entry.accessToken = token
	entry.expiresAt = ts.now().Add(time.Duration(expiresIn) * time.Second)
	return entry.accessToken, nil
}

func (ts *TokenSource) entryFor(tenantID string) *tenantTokenEntry {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	e, ok := ts.entries[tenantID]
	if !ok {
		e = &tenantTokenEntry{}
		ts.entries[tenantID] = e
	}
	return e
}

type tokenSuccessResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorCodes       []int  `json:"error_codes"`
}

func (ts *TokenSource) fetchToken(ctx context.Context, tenantID string) (string, int, error) {
	now := ts.now()
	if ts.Cert.Expired(now) {
		return "", 0, &TokenError{
			Code:        "certificate_expired",
			Description: fmt.Sprintf("certificate not valid after %s", ts.Cert.NotAfter()),
			Err:         ErrCertificateInvalid,
		}
	}

	endpoint := strings.TrimRight(ts.AuthorityBase, "/") + "/" + tenantID + "/oauth2/v2.0/token"

	assertion, err := buildClientAssertion(ts.Cert, ts.ClientID, endpoint, now)
	if err != nil {
		return "", 0, err
	}

	form := url.Values{}
	form.Set("grant_type", grantTypeClientCreds)
	form.Set("client_id", ts.ClientID)
	form.Set("client_assertion_type", assertionType)
	form.Set("client_assertion", assertion)
	form.Set("scope", ts.Scope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("msgraph: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ts.HTTPClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("msgraph: token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("msgraph: read token response: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return "", 0, &ThrottledError{RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	}

	if resp.StatusCode != http.StatusOK {
		var e tokenErrorResponse
		if jsonErr := json.Unmarshal(body, &e); jsonErr == nil && e.Error != "" {
			return "", 0, classifyTokenError(e.Error, e.ErrorDescription, e.ErrorCodes)
		}
		return "", 0, fmt.Errorf("msgraph: token endpoint returned status %d", resp.StatusCode)
	}

	var s tokenSuccessResponse
	if err := json.Unmarshal(body, &s); err != nil {
		return "", 0, fmt.Errorf("msgraph: decode token response: %w", err)
	}
	if s.AccessToken == "" {
		return "", 0, fmt.Errorf("msgraph: token response missing access_token")
	}
	return s.AccessToken, s.ExpiresIn, nil
}
