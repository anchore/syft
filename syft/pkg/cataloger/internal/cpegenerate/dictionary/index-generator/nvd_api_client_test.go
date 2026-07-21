package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildDateChunks(t *testing.T) {
	tests := []struct {
		name           string
		start          time.Time
		end            time.Time
		expectedChunks int
		validateChunks func(t *testing.T, chunks []dateChunk)
	}{
		{
			name:           "single chunk when range is under 120 days",
			start:          time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			end:            time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC), // 31 days
			expectedChunks: 1,
			validateChunks: func(t *testing.T, chunks []dateChunk) {
				assert.Equal(t, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), chunks[0].start)
				assert.Equal(t, time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC), chunks[0].end)
			},
		},
		{
			name:           "single chunk when range is exactly 120 days",
			start:          time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			end:            time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC), // 120 days
			expectedChunks: 1,
			validateChunks: func(t *testing.T, chunks []dateChunk) {
				assert.Equal(t, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), chunks[0].start)
				assert.Equal(t, time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC), chunks[0].end)
			},
		},
		{
			name:           "two chunks when range is 121 days",
			start:          time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			end:            time.Date(2025, 5, 2, 0, 0, 0, 0, time.UTC), // 121 days
			expectedChunks: 2,
			validateChunks: func(t *testing.T, chunks []dateChunk) {
				// first chunk: Jan 1 to May 1 (120 days)
				assert.Equal(t, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), chunks[0].start)
				assert.Equal(t, time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC), chunks[0].end)
				// second chunk: May 1 to May 2 (1 day)
				assert.Equal(t, time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC), chunks[1].start)
				assert.Equal(t, time.Date(2025, 5, 2, 0, 0, 0, 0, time.UTC), chunks[1].end)
			},
		},
		{
			name:           "multiple chunks for a full year",
			start:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			end:            time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), // 366 days (leap year)
			expectedChunks: 4,
			validateChunks: func(t *testing.T, chunks []dateChunk) {
				// verify chunks are contiguous (each chunk starts where previous ended)
				for i := 1; i < len(chunks); i++ {
					assert.Equal(t, chunks[i-1].end, chunks[i].start, "chunks should be contiguous")
				}
				// verify first and last
				assert.Equal(t, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), chunks[0].start)
				assert.Equal(t, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), chunks[len(chunks)-1].end)
			},
		},
		{
			name:           "empty result when start equals end",
			start:          time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			end:            time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			expectedChunks: 0,
		},
		{
			name:           "empty result when start is after end",
			start:          time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
			end:            time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			expectedChunks: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunks := buildDateChunks(tt.start, tt.end)
			assert.Len(t, chunks, tt.expectedChunks)
			if tt.validateChunks != nil && len(chunks) > 0 {
				tt.validateChunks(t, chunks)
			}
		})
	}
}

func TestBuildDateChunks_ChunkSizeNeverExceeds120Days(t *testing.T) {
	// test with various date ranges to ensure no chunk exceeds 120 days
	testCases := []struct {
		start time.Time
		end   time.Time
	}{
		{time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
		{time.Date(2023, 6, 15, 0, 0, 0, 0, time.UTC), time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)},
		{time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2024, 12, 31, 0, 0, 0, 0, time.UTC)},
	}

	for _, tc := range testCases {
		chunks := buildDateChunks(tc.start, tc.end)
		for i, chunk := range chunks {
			days := chunk.end.Sub(chunk.start).Hours() / 24
			assert.LessOrEqual(t, days, float64(maxDateRangeDays),
				"chunk %d exceeds max days: start=%s, end=%s, days=%.0f",
				i, chunk.start.Format("2006-01-02"), chunk.end.Format("2006-01-02"), days)
		}
	}
}

// mockResponseBody creates an io.ReadCloser from a string for testing
type mockReadCloser struct {
	io.Reader
	closed bool
}

func (m *mockReadCloser) Close() error {
	m.closed = true
	return nil
}

func newMockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       &mockReadCloser{Reader: strings.NewReader(body)},
	}
}

func TestCheckHTTPStatus(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		body          string
		expectError   bool
		errorContains string
	}{
		{
			name:        "200 OK returns nil",
			statusCode:  http.StatusOK,
			body:        `{"totalResults": 0}`,
			expectError: false,
		},
		{
			name:          "404 returns error",
			statusCode:    http.StatusNotFound,
			body:          "",
			expectError:   true,
			errorContains: "status 404",
		},
		{
			name:          "400 Bad Request returns error with body",
			statusCode:    http.StatusBadRequest,
			body:          "Both lastModStartDate and lastModEndDate are required",
			expectError:   true,
			errorContains: "lastModStartDate and lastModEndDate are required",
		},
		{
			name:          "500 Internal Server Error returns error",
			statusCode:    http.StatusInternalServerError,
			body:          "Internal server error",
			expectError:   true,
			errorContains: "status 500",
		},
		{
			name:          "503 Service Unavailable returns error",
			statusCode:    http.StatusServiceUnavailable,
			body:          "Service temporarily unavailable",
			expectError:   true,
			errorContains: "status 503",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := newMockResponse(tt.statusCode, tt.body)
			err := checkHTTPStatus(resp)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				// verify body was closed on error
				assert.True(t, resp.Body.(*mockReadCloser).closed, "response body should be closed on error")
			} else {
				require.NoError(t, err)
				// verify body was NOT closed on success (caller needs to read it)
				assert.False(t, resp.Body.(*mockReadCloser).closed, "response body should not be closed on success")
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected time.Duration
	}{
		{
			name:     "empty header returns 0",
			header:   "",
			expected: 0,
		},
		{
			name:     "numeric seconds",
			header:   "30",
			expected: 30 * time.Second,
		},
		{
			name:     "numeric seconds - larger value",
			header:   "120",
			expected: 120 * time.Second,
		},
		{
			name:     "invalid value returns 0",
			header:   "not-a-number",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseRetryAfter(tt.header)
			assert.Equal(t, tt.expected, result)
		})
	}
}
