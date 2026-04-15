package model

import (
	"encoding/json"
	"runtime/debug"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDocumentUnmarshalJSON_NoInfiniteRecursion guards against the regression
// where encoding/json/v2 (GOEXPERIMENT=jsonv2) would call UnmarshalJSON
// recursively on the alias type, causing a goroutine stack overflow.
// See: https://github.com/golang/go/issues/75361
func TestDocumentUnmarshalJSON_NoInfiniteRecursion(t *testing.T) {
	data := `{
		"artifacts": [
			{"id": "1", "name": "pkg-a", "version": "1.0", "type": "npm", "foundBy": "cataloger", "locations": [], "licenses": [], "language": "javascript", "cpes": [], "purl": "pkg:npm/pkg-a@1.0"},
			{"id": "2", "name": "pkg-b", "version": "2.0", "type": "gem", "foundBy": "cataloger", "locations": [], "licenses": [], "language": "ruby",      "cpes": [], "purl": "pkg:gem/pkg-b@2.0"}
		],
		"schema": {"version": "16.0.0", "url": "https://example.com"},
		"descriptor": {"name": "syft", "version": "1.0.0"}
	}`

	// Shrink the max goroutine stack to 8MB so that infinite recursion
	// (golang/go#75361 — encoding/json/v2 re-dispatching to UnmarshalJSON
	// via type Alias *Document) overflows quickly rather than after minutes.
	old := debug.SetMaxStack(8 * 1024 * 1024)
	defer debug.SetMaxStack(old)

	done := make(chan error, 1)
	go func() {
		var doc Document
		done <- json.Unmarshal([]byte(data), &doc)
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("json.Unmarshal did not complete — likely infinite recursion in UnmarshalJSON")
	}
}

func TestDocumentUnmarshalJSON_SchemaDetection(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		modes    []int
	}{
		{
			name: "schema version 1.0.0 + anchorectl",
			jsonData: `{
				"files": [
					{"metadata": {"mode": 493}},
					{"metadata": {"mode": 420}}
				],
				"schema": {"version": "1.0.0"},
                "descriptor": {
					"name": "anchorectl"
				}
			}`,
			modes: []int{755, 644},
		},
		{
			name: "schema version 1.0.0 + syft",
			jsonData: `{
				"files": [
					{"metadata": {"mode": 755}},
					{"metadata": {"mode": 644}}
				],
				"schema": {"version": "1.0.0"},
                "descriptor": {
					"name": "syft"
				}
			}`,
			modes: []int{755, 644},
		},
		{
			name: "schema version 2.0.0 + anchorectl",
			jsonData: `{
				"files": [
					{"metadata": {"mode": 755}},
					{"metadata": {"mode": 644}}
				],
				"schema": {"version": "2.0.0"},
                "descriptor": {
					"name": "anchorectl"
				}
			}`,
			modes: []int{755, 644},
		},
		{
			name: "missing schema version should not convert modes",
			jsonData: `{
				"files": [
					{"metadata": {"mode": 755}}
				],
				"schema": {}
			}`,
			modes: []int{755},
		},
		{
			name: "empty files array with version 1.0.0",
			jsonData: `{
				"files": [],
				"schema": {"version": "1.0.0"},
                "descriptor": {
					"name": "anchorectl"
				}
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var doc Document

			err := json.Unmarshal([]byte(tt.jsonData), &doc)
			if err != nil {
				t.Fatalf("Failed to unmarshal JSON: %v", err)
			}

			var modes []int
			for _, file := range doc.Files {
				modes = append(modes, file.Metadata.Mode)
			}

			require.Len(t, doc.Files, len(tt.modes), "Unexpected number of files")
			assert.Equal(t, tt.modes, modes, "File modes do not match expected values")
		})
	}
}
