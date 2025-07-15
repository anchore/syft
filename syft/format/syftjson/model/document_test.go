package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
