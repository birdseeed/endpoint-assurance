package feedback

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"patched.im/api/internal/webhook"
	"strings"
	"time"
	"unicode"
)

const maxScreenshotAttempts = 5

type screenshotPUTError struct{ cause error }

func (e screenshotPUTError) Error() string { return "screenshot PUT transport failed" }
func (e screenshotPUTError) Unwrap() error { return e.cause }

func validScreenshotAssetURL(raw string) bool {
	for _, r := range raw {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && !strings.ContainsAny(raw, "<>\r\n\\")
}

func validSignedUploadHeader(key, value string) bool {
	if key == "" || strings.TrimSpace(value) == "" {
		return false
	}
	for _, r := range key {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || strings.ContainsRune("!#$%&'*+-.^_`|~", r)) {
			return false
		}
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (c *LinearClient) uploadScreenshot(ctx context.Context, shot *Screenshot) (string, error) {
	if shot == nil || len(shot.Bytes) == 0 {
		return "", fmt.Errorf("missing screenshot bytes")
	}
	var out struct {
		FileUpload struct {
			Success    bool `json:"success"`
			UploadFile *struct {
				UploadURL string `json:"uploadUrl"`
				AssetURL  string `json:"assetUrl"`
				Headers   []struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				} `json:"headers"`
			} `json:"uploadFile"`
		} `json:"fileUpload"`
	}
	if err := c.do(ctx, `mutation($contentType:String!,$filename:String!,$size:Int!){fileUpload(contentType:$contentType,filename:$filename,size:$size){success uploadFile{uploadUrl assetUrl headers{key value}}}}`, map[string]any{"contentType": shot.ContentType, "filename": shot.Filename, "size": len(shot.Bytes)}, &out); err != nil {
		return "", err
	}
	f := out.FileUpload.UploadFile
	if !out.FileUpload.Success || f == nil || !validScreenshotAssetURL(f.AssetURL) {
		return "", fmt.Errorf("Linear fileUpload returned invalid upload metadata")
	}
	if err := webhook.ValidateDestination(f.UploadURL); err != nil {
		return "", fmt.Errorf("Linear upload destination: %w", err)
	}
	headers := map[string]string{"Content-Type": shot.ContentType, "Cache-Control": "public, max-age=31536000"}
	// Canonicalise keys so signed headers override defaults case-insensitively.
	signedHeaderKeys := make(map[string]struct{}, len(f.Headers))
	for _, h := range f.Headers {
		if !validSignedUploadHeader(h.Key, h.Value) {
			return "", fmt.Errorf("Linear fileUpload returned invalid signed upload header")
		}
		key := http.CanonicalHeaderKey(h.Key)
		if _, duplicate := signedHeaderKeys[key]; duplicate {
			return "", fmt.Errorf("Linear fileUpload returned duplicate signed upload header")
		}
		signedHeaderKeys[key] = struct{}{}
		headers[key] = h.Value
	}
	put := c.put
	if put == nil {
		put = webhook.PutHardened
	}
	uploadCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	status, err := put(uploadCtx, f.UploadURL, headers, shot.Bytes)
	if err != nil {
		// Transport errors can include signed query credentials in the URL. Keep
		// the stored/logged error safe while preserving errors.Is for callers.
		return "", screenshotPUTError{cause: err}
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("screenshot PUT HTTP %d", status)
	}
	return f.AssetURL, nil
}
