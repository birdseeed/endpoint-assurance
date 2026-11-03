package msgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultGraphBaseURL = "https://graph.microsoft.com/v1.0"
	// maxThrottleRetries bounds how many times one page fetch will honour a
	// 429 before giving up and surfacing ThrottledError to the caller. This
	// is a generic client; deciding whether/when to try the whole
	// reconciliation run again is the caller's job, not this loop's.
	maxThrottleRetries = 5
)

// Client is a generic, read-only Microsoft Graph request helper: bearer
// auth via a TokenSource, $select/query passthrough, and @odata.nextLink
// paging to full exhaustion. It has no knowledge of any specific Graph
// resource (no /devices, no /managedDevices) — that belongs to whatever
// calls this package.
type Client struct {
	Tokens     *TokenSource
	HTTPClient *http.Client
	BaseURL    string // overridable for tests; defaults to defaultGraphBaseURL

	sleep func(context.Context, time.Duration) error
}

// NewClient builds a Client backed by tokens.
func NewClient(tokens *TokenSource) *Client {
	return &Client{
		Tokens:     tokens,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		BaseURL:    defaultGraphBaseURL,
		sleep:      contextSleep,
	}
}

type graphPage struct {
	Value    []json.RawMessage `json:"value"`
	NextLink string            `json:"@odata.nextLink"`
}

type graphErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// GetAll issues a GET against path (relative to BaseURL) for tenantID,
// passing query straight through (e.g. $select, $filter), and follows
// @odata.nextLink until Graph reports no further pages. It returns every
// item from every page, in order.
func (c *Client) GetAll(ctx context.Context, tenantID, path string, query url.Values) ([]json.RawMessage, error) {
	reqURL := c.BaseURL + path
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}

	var results []json.RawMessage
	for reqURL != "" {
		page, err := c.getPage(ctx, tenantID, reqURL)
		if err != nil {
			return nil, err
		}
		results = append(results, page.Value...)
		if page.NextLink != "" {
			if err := c.validateNextLink(page.NextLink); err != nil {
				return nil, err
			}
		}
		reqURL = page.NextLink
	}
	return results, nil
}

// validateNextLink refuses to follow an @odata.nextLink whose host doesn't
// match this client's own BaseURL. Every getPage request attaches our bearer
// token, so blindly following a paging link Graph handed back would leak
// that token to whatever host is named there — defence in depth against a
// compromised or malformed Graph response, not just a well-formed one.
func (c *Client) validateNextLink(next string) error {
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return fmt.Errorf("msgraph: client has an invalid BaseURL: %w", err)
	}
	nu, err := url.Parse(next)
	if err != nil {
		return fmt.Errorf("msgraph: @odata.nextLink is not a valid URL: %w", err)
	}
	if nu.Scheme != base.Scheme || !strings.EqualFold(nu.Host, base.Host) {
		return fmt.Errorf("msgraph: refusing to follow @odata.nextLink to unexpected host %q (expected %q)", nu.Host, base.Host)
	}
	return nil
}

func (c *Client) getPage(ctx context.Context, tenantID, reqURL string) (*graphPage, error) {
	body, err := c.doRequest(ctx, tenantID, reqURL)
	if err != nil {
		return nil, err
	}
	var page graphPage
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("msgraph: decode graph page: %w", err)
	}
	return &page, nil
}

// Get issues a GET against path (relative to BaseURL) for tenantID, passing
// query straight through, and returns the single JSON object in the
// response body verbatim. Unlike GetAll, it does not expect (and does not
// follow) a paged "value"/"@odata.nextLink" envelope — Graph's get-by-id
// endpoints (e.g. /deviceManagement/deviceCompliancePolicies/{id}) return
// the object directly. Same auth, retry and throttle handling as GetAll.
func (c *Client) Get(ctx context.Context, tenantID, path string, query url.Values) (json.RawMessage, error) {
	reqURL := c.BaseURL + path
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}
	body, err := c.doRequest(ctx, tenantID, reqURL)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

// doRequest performs one authenticated GET against reqURL, transparently
// retrying on 429 (honouring Retry-After) up to maxThrottleRetries, and
// returns the raw response body on success. Shared by getPage (which
// interprets the body as a paged envelope) and Get (which returns it
// verbatim) so both stay on exactly one auth/retry/throttle implementation.
func (c *Client) doRequest(ctx context.Context, tenantID, reqURL string) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		token, err := c.Tokens.Token(ctx, tenantID)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("msgraph: build graph request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("msgraph: graph request: %w", err)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("msgraph: read graph response: %w", readErr)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			wait := parseRetryAfter(resp.Header.Get("Retry-After"))
			if attempt >= maxThrottleRetries {
				return nil, &ThrottledError{RetryAfter: wait}
			}
			if err := c.sleep(ctx, wait); err != nil {
				return nil, err
			}
			continue
		}

		if resp.StatusCode != http.StatusOK {
			var eb graphErrorBody
			_ = json.Unmarshal(body, &eb)
			return nil, classifyGraphError(resp.StatusCode, eb.Error.Code, eb.Error.Message)
		}

		return body, nil
	}
}
