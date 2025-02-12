package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fgravato/lookoutmobile-scanner/internal/config"
	"github.com/fgravato/lookoutmobile-scanner/pkg/errors"
)

// Client handles all API interactions
type Client struct {
	baseURL        string
	applicationKey string
	httpClient     *http.Client
	accessToken    string
	tokenExpiry    time.Time
	maxRetries     int
	retryDelay     time.Duration
}

// NewClient creates a new API client
func NewClient(cfg config.APIConfig) *Client {
	return &Client{
		baseURL:        cfg.BaseURL,
		applicationKey: cfg.ApplicationKey,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		maxRetries: cfg.MaxRetries,
		retryDelay: cfg.RetryDelay,
	}
}

// doRequest performs an HTTP request with retries and error handling
func (c *Client) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", c.baseURL, path)
	var resp *http.Response
	var err error

	// Ensure we have a valid token
	if err := c.ensureValidToken(ctx); err != nil {
		return nil, fmt.Errorf("ensuring valid token: %w", err)
	}

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			if attempt > 0 {
				time.Sleep(c.retryDelay)
			}

			req, err := http.NewRequestWithContext(ctx, method, url, body)
			if err != nil {
				return nil, fmt.Errorf("creating request: %w", err)
			}

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))
			req.Header.Set("Accept", "application/json")
			if body != nil {
				req.Header.Set("Content-Type", "application/json")
			}

			resp, err = c.httpClient.Do(req)
			if err != nil {
				if attempt == c.maxRetries {
					return nil, fmt.Errorf("request failed after %d retries: %w", c.maxRetries, err)
				}
				continue
			}

			// Handle rate limiting
			if resp.StatusCode == http.StatusTooManyRequests {
				if attempt == c.maxRetries {
					return nil, errors.NewAPIError(resp.StatusCode, "rate limit exceeded", nil)
				}
				resp.Body.Close()
				continue
			}

			// Handle other error status codes
			if resp.StatusCode >= 400 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				details := map[string]interface{}{
					"status_code": resp.StatusCode,
					"body":        string(body),
				}
				return nil, errors.NewAPIError(resp.StatusCode, fmt.Sprintf("API request failed: %s", string(body)), details)
			}

			return resp, nil
		}
	}

	return resp, err
}

// ensureValidToken ensures we have a valid access token
func (c *Client) ensureValidToken(ctx context.Context) error {
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		return nil
	}

	data := "grant_type=client_credentials"
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/oauth2/token",
		strings.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating token request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.applicationKey))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("requesting token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return errors.NewAPIError(resp.StatusCode,
			fmt.Sprintf("token request failed: %s", string(body)), nil)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("decoding token response: %w", err)
	}

	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return nil
}

// GetDevices retrieves a list of devices
func (c *Client) GetDevices(ctx context.Context, lastOID string, limit int) (*DevicesResponse, error) {
	url := fmt.Sprintf("/mra/api/v2/devices?limit=%d", limit)
	if lastOID != "" {
		url += "&oid=" + lastOID
	}

	resp, err := c.doRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("getting devices: %w", err)
	}
	defer resp.Body.Close()

	var devicesResp DevicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&devicesResp); err != nil {
		return nil, fmt.Errorf("decoding devices response: %w", err)
	}

	return &devicesResp, nil
}

// GetVulnerabilities retrieves vulnerabilities for a device
func (c *Client) GetVulnerabilities(ctx context.Context, platform, version string) (*VulnerabilitiesResponse, error) {
	if version == "" {
		return nil, errors.NewValidationError("version", version, "version is required")
	}

	var url string
	switch platform {
	case "ANDROID":
		if !strings.Contains(version, "-") {
			return nil, errors.NewValidationError("version", version, "invalid security patch level format")
		}
		url = fmt.Sprintf("/mra/api/v2/os-vulns/android?aspl=%s", version)
	case "IOS":
		url = fmt.Sprintf("/mra/api/v2/os-vulns/ios?version=%s", version)
	default:
		return nil, errors.NewValidationError("platform", platform, "invalid platform")
	}

	resp, err := c.doRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("getting vulnerabilities: %w", err)
	}
	defer resp.Body.Close()

	var vulnsResp VulnerabilitiesResponse
	if err := json.NewDecoder(resp.Body).Decode(&vulnsResp); err != nil {
		return nil, fmt.Errorf("decoding vulnerabilities response: %w", err)
	}

	return &vulnsResp, nil
}
