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

	// NVD API has a maximum date range of 120 days for queries with date filters
	maxDateRangeDays = 120
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

// FetchProductsSince fetches all products modified since the given date.
// If lastModStartDate is zero, fetches all products (no date filter).
// If lastModStartDate is set, fetches in 120-day chunks (NVD API limit) from that date to now.
// Returns partial results on error so progress can be saved.
func (c *NVDAPIClient) FetchProductsSince(ctx context.Context, lastModStartDate time.Time) ([]NVDProduct, error) {
	// if no date filter, fetch all products in a single pass
	if lastModStartDate.IsZero() {
		return c.fetchDateRange(ctx, time.Time{}, time.Time{})
	}

	// fetch in 120-day chunks from lastModStartDate to now
	chunks := buildDateChunks(lastModStartDate, time.Now().UTC())
	if len(chunks) > 1 {
		fmt.Printf("Date range spans %d chunks of up to %d days each\n", len(chunks), maxDateRangeDays)
	}

	var allProducts []NVDProduct
	for i, chunk := range chunks {
		if len(chunks) > 1 {
			fmt.Printf("Fetching chunk %d/%d: %s to %s\n", i+1, len(chunks),
				chunk.start.Format("2006-01-02"), chunk.end.Format("2006-01-02"))
		}

		products, err := c.fetchDateRange(ctx, chunk.start, chunk.end)
		if err != nil {
			// return partial results so caller can save progress
			return allProducts, err
		}

		allProducts = append(allProducts, products...)
		if len(chunks) > 1 {
			fmt.Printf("Chunk %d complete: %d products (total so far: %d)\n", i+1, len(products), len(allProducts))
		}
	}

	fmt.Printf("Fetched %d products total\n", len(allProducts))
	return allProducts, nil
}

// dateChunk represents a date range for fetching
type dateChunk struct {
	start time.Time
	end   time.Time
}

// buildDateChunks splits a date range into chunks of maxDateRangeDays
func buildDateChunks(start, end time.Time) []dateChunk {
	var chunks []dateChunk
	chunkStart := start

	for chunkStart.Before(end) {
		chunkEnd := chunkStart.AddDate(0, 0, maxDateRangeDays)
		if chunkEnd.After(end) {
			chunkEnd = end
		}
		chunks = append(chunks, dateChunk{start: chunkStart, end: chunkEnd})
		chunkStart = chunkEnd
	}

	return chunks
}

// fetchDateRange fetches all products within a single date range (must be <= 120 days).
// If start and end are both zero, fetches all products without date filtering.
func (c *NVDAPIClient) fetchDateRange(ctx context.Context, start, end time.Time) ([]NVDProduct, error) {
	var products []NVDProduct
	startIndex := 0

	for {
		resp, err := c.fetchPage(ctx, startIndex, start, end)
		if err != nil {
			return products, fmt.Errorf("failed to fetch page at index %d: %w", startIndex, err)
		}

		products = append(products, resp.Products...)
		fmt.Printf("  Fetched %d/%d products...\n", len(products), resp.TotalResults)

		// check if we've fetched all results
		if startIndex+resp.ResultsPerPage >= resp.TotalResults {
			break
		}

		startIndex += resp.ResultsPerPage
	}

	return products, nil
}

// fetchPage fetches a single page of results from the NVD API with retry logic for rate limiting
// if both start and end are zero, fetches without date filtering
// if start and end are set, they must form a range <= 120 days (enforced by caller)
func (c *NVDAPIClient) fetchPage(ctx context.Context, startIndex int, start, end time.Time) (NVDProductsResponse, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		// wait for rate limiter
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return NVDProductsResponse{}, fmt.Errorf("rate limiter error: %w", err)
		}

		// build request URL
		url := fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d", nvdProductsAPIURL, resultsPerPage, startIndex)

		// add date range if specified (incremental update)
		// NVD API requires both lastModStartDate and lastModEndDate when either is present
		if !start.IsZero() && !end.IsZero() {
			// NVD API requires this format: 2024-01-01T00:00:00.000
			startStr := start.Format("2006-01-02T15:04:05.000")
			endStr := end.Format("2006-01-02T15:04:05.000")
			url += fmt.Sprintf("&lastModStartDate=%s&lastModEndDate=%s", startStr, endStr)
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

		// check for error status codes
		if err := checkHTTPStatus(httpResp); err != nil {
			return NVDProductsResponse{}, err
		}

		// parse response
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

// checkHTTPStatus returns an error for non-200 status codes.
// NVD API returns 200 with TotalResults=0 when there are no results,
// so any non-200 status (including 404) indicates an actual error.
func checkHTTPStatus(httpResp *http.Response) error {
	if httpResp.StatusCode == http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(httpResp.Body)
	httpResp.Body.Close()
	return fmt.Errorf("NVD API error (status %d): %s", httpResp.StatusCode, string(body))
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
