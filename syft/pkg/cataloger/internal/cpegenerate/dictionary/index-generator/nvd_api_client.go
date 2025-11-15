package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/time/rate"
)

const (
	nvdProductsAPIURL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
	resultsPerPage    = 2000 // maximum allowed by NVD API

	// rate limits per NVD API documentation
	unauthenticatedRequestsPer30Seconds = 5
	authenticatedRequestsPer30Seconds   = 50

	// retry configuration for rate limiting
	maxRetries     = 5
	baseRetryDelay = 30 * time.Second // NVD uses 30-second rolling windows
)

// NVDAPIClient handles communication with the NVD Products API
type NVDAPIClient struct {
	httpClient  *http.Client
	rateLimiter *rate.Limiter
	apiKey      string
}

// NVDProductsResponse represents the JSON response from the NVD Products API
type NVDProductsResponse struct {
	ResultsPerPage int          `json:"resultsPerPage"`
	StartIndex     int          `json:"startIndex"`
	TotalResults   int          `json:"totalResults"`
	Format         string       `json:"format"`
	Version        string       `json:"version"`
	Timestamp      string       `json:"timestamp"`
	Products       []NVDProduct `json:"products"`
}

// NVDProduct represents a single product entry from the API
type NVDProduct struct {
	CPE NVDProductDetails `json:"cpe"`
}

// NVDProductDetails contains the CPE and reference information
type NVDProductDetails struct {
	CPEName      string            `json:"cpeName"`
	Deprecated   bool              `json:"deprecated"`
	DeprecatedBy []NVDDeprecatedBy `json:"deprecatedBy,omitempty"`
	CPENameID    string            `json:"cpeNameId"`
	Created      string            `json:"created"`
	LastModified string            `json:"lastModified"`
	Titles       []NVDTitle        `json:"titles"`
	Refs         []NVDRef          `json:"refs"`
}

// NVDTitle represents a title in a specific language
type NVDTitle struct {
	Title string `json:"title"`
	Lang  string `json:"lang"`
}

// NVDRef represents a reference URL
type NVDRef struct {
	Ref  string `json:"ref"`
	Type string `json:"type,omitempty"`
}

// NVDDeprecatedBy represents a CPE that replaces a deprecated one
type NVDDeprecatedBy struct {
	CPEName   string `json:"cpeName"`
	CPENameID string `json:"cpeNameId"`
}

// NewNVDAPIClient creates a new NVD API client
// it reads the NVD_API_KEY environment variable for authenticated requests
func NewNVDAPIClient() *NVDAPIClient {
	apiKey := os.Getenv("NVD_API_KEY")

	// determine rate limit based on authentication
	requestsPer30Seconds := unauthenticatedRequestsPer30Seconds
	if apiKey != "" {
		requestsPer30Seconds = authenticatedRequestsPer30Seconds
		fmt.Printf("Using authenticated NVD API access (%d requests per 30 seconds)\n", requestsPer30Seconds)
	} else {
		fmt.Printf("Using unauthenticated NVD API access (%d requests per 30 seconds)\n", requestsPer30Seconds)
		fmt.Println("Set NVD_API_KEY environment variable for higher rate limits")
	}

	// create rate limiter with 10% safety margin to avoid hitting limits
	// X requests per 30 seconds * 0.9 = (X * 0.9) / 30 requests per second
	effectiveRate := float64(requestsPer30Seconds) * 0.9 / 30.0
	limiter := rate.NewLimiter(rate.Limit(effectiveRate), 1)
	fmt.Printf("Rate limiter configured: %.2f requests/second (with 10%% safety margin)\n", effectiveRate)

	return &NVDAPIClient{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		rateLimiter: limiter,
		apiKey:      apiKey,
	}
}

// PageCallback is called after each page is successfully fetched
// it receives the startIndex and the response for that page
type PageCallback func(startIndex int, response NVDProductsResponse) error

// FetchProductsSince fetches all products modified since the given date
// if lastModStartDate is zero, fetches all products
// calls onPageFetched callback after each successful page fetch for incremental saving
// if resumeFromIndex > 0, starts fetching from that index
func (c *NVDAPIClient) FetchProductsSince(ctx context.Context, lastModStartDate time.Time, resumeFromIndex int, onPageFetched PageCallback) error {
	startIndex := resumeFromIndex

	for {
		resp, err := c.fetchPage(ctx, startIndex, lastModStartDate)
		if err != nil {
			return fmt.Errorf("failed to fetch page at index %d: %w", startIndex, err)
		}

		// call callback to save progress immediately
		if onPageFetched != nil {
			if err := onPageFetched(startIndex, resp); err != nil {
				return fmt.Errorf("callback failed at index %d: %w", startIndex, err)
			}
		}

		// check if we've fetched all results
		if startIndex+resp.ResultsPerPage >= resp.TotalResults {
			fmt.Printf("Fetched %d/%d products (complete)\n", resp.TotalResults, resp.TotalResults)
			break
		}

		startIndex += resp.ResultsPerPage
		fmt.Printf("Fetched %d/%d products...\n", startIndex, resp.TotalResults)
	}

	return nil
}

// fetchPage fetches a single page of results from the NVD API with retry logic for rate limiting
func (c *NVDAPIClient) fetchPage(ctx context.Context, startIndex int, lastModStartDate time.Time) (NVDProductsResponse, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		// wait for rate limiter
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return NVDProductsResponse{}, fmt.Errorf("rate limiter error: %w", err)
		}

		// build request URL
		url := fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d", nvdProductsAPIURL, resultsPerPage, startIndex)

		// add date range if specified (incremental update)
		if !lastModStartDate.IsZero() {
			// NVD API requires RFC3339 format: 2024-01-01T00:00:00.000
			lastModStartStr := lastModStartDate.Format("2006-01-02T15:04:05.000")
			url += fmt.Sprintf("&lastModStartDate=%s", lastModStartStr)
		}

		// create request
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return NVDProductsResponse{}, fmt.Errorf("failed to create request: %w", err)
		}

		// add API key header if available
		if c.apiKey != "" {
			req.Header.Set("apiKey", c.apiKey)
		}

		req.Header.Set("User-Agent", "syft-cpe-dictionary-generator")

		// execute request
		httpResp, err := c.httpClient.Do(req)
		if err != nil {
			return NVDProductsResponse{}, fmt.Errorf("failed to execute request: %w", err)
		}

		// handle rate limiting
		if httpResp.StatusCode == http.StatusTooManyRequests {
			lastErr = c.handleRateLimit(ctx, httpResp, attempt)
			continue // retry
		}

		// handle HTTP status codes
		statusResponse, handled, err := c.handleHTTPStatus(httpResp, startIndex)
		if handled {
			// either error or special case (404 with empty results)
			return statusResponse, err
		}

		// success - parse response
		var response NVDProductsResponse
		if err := json.NewDecoder(httpResp.Body).Decode(&response); err != nil {
			httpResp.Body.Close()
			return NVDProductsResponse{}, fmt.Errorf("failed to decode response: %w", err)
		}

		httpResp.Body.Close()
		return response, nil
	}

	return NVDProductsResponse{}, fmt.Errorf("max retries (%d) exceeded: %w", maxRetries, lastErr)
}

// handleRateLimit handles HTTP 429 responses by parsing Retry-After and waiting
func (c *NVDAPIClient) handleRateLimit(ctx context.Context, httpResp *http.Response, attempt int) error {
	body, _ := io.ReadAll(httpResp.Body)
	httpResp.Body.Close()

	// parse Retry-After header
	retryAfter := parseRetryAfter(httpResp.Header.Get("Retry-After"))
	if retryAfter == 0 {
		// use exponential backoff if no Retry-After header
		retryAfter = baseRetryDelay * time.Duration(1<<uint(attempt))
	}

	err := fmt.Errorf("rate limited (429): %s", string(body))
	fmt.Printf("Rate limited (429), retrying in %v (attempt %d/%d)...\n", retryAfter, attempt+1, maxRetries)

	select {
	case <-time.After(retryAfter):
		return err // return to retry
	case <-ctx.Done():
		return ctx.Err()
	}
}

// handleHTTPStatus handles non-429 HTTP status codes
// returns (response, handled, error) where:
//   - handled=true means the status was processed (either success case like 404 or error)
//   - handled=false means continue to normal response parsing
func (c *NVDAPIClient) handleHTTPStatus(httpResp *http.Response, startIndex int) (NVDProductsResponse, bool, error) {
	// handle 404 as "no results found" (common when querying recent dates with no updates)
	if httpResp.StatusCode == http.StatusNotFound {
		httpResp.Body.Close()
		return NVDProductsResponse{
			ResultsPerPage: 0,
			StartIndex:     startIndex,
			TotalResults:   0,
			Products:       []NVDProduct{},
		}, true, nil
	}

	// check for other non-200 status codes
	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(httpResp.Body)
		httpResp.Body.Close()
		return NVDProductsResponse{}, true, fmt.Errorf("unexpected status code %d: %s", httpResp.StatusCode, string(body))
	}

	// status OK - let caller parse response
	return NVDProductsResponse{}, false, nil
}

// parseRetryAfter parses the Retry-After header from HTTP 429 responses
// returns 0 if the header is missing or invalid
func parseRetryAfter(header string) time.Duration {
	if header == "" {
		return 0
	}

	// try parsing as seconds (most common format)
	if seconds, err := strconv.Atoi(header); err == nil {
		return time.Duration(seconds) * time.Second
	}

	// try parsing as HTTP date (less common)
	if t, err := time.Parse(time.RFC1123, header); err == nil {
		duration := time.Until(t)
		if duration > 0 {
			return duration
		}
	}

	return 0
}
