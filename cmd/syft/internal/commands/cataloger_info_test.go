package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/capabilities"
)

func TestParseEnrichmentMode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    capabilities.EnrichmentMode
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:  "offline mode",
			input: "offline",
			want:  capabilities.OfflineMode,
		},
		{
			name:  "online mode",
			input: "online",
			want:  capabilities.OnlineMode,
		},
		{
			name:  "tool-execution mode",
			input: "tool-execution",
			want:  capabilities.ToolExecutionMode,
		},
		{
			name:    "invalid mode",
			input:   "invalid",
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			got, err := parseEnrichmentMode(tt.input)
			tt.wantErr(t, err)

			if err != nil {
				return
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFilterCatalogersByName(t *testing.T) {
	catalogers := []capabilities.CatalogerEntry{
		{Name: "cataloger-a"},
		{Name: "cataloger-b"},
		{Name: "cataloger-c"},
	}

	tests := []struct {
		name      string
		names     []string
		wantNames []string
	}{
		{
			name:      "filter single cataloger",
			names:     []string{"cataloger-a"},
			wantNames: []string{"cataloger-a"},
		},
		{
			name:      "filter multiple catalogers",
			names:     []string{"cataloger-a", "cataloger-c"},
			wantNames: []string{"cataloger-a", "cataloger-c"},
		},
		{
			name:      "filter non-existent cataloger",
			names:     []string{"cataloger-x"},
			wantNames: []string{},
		},
		{
			name:      "empty filter returns empty",
			names:     []string{},
			wantNames: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterCatalogersByName(catalogers, tt.names)

			var gotNames []string
			for _, cat := range got {
				gotNames = append(gotNames, cat.Name)
			}

			if tt.wantNames == nil {
				tt.wantNames = []string{}
			}
			if gotNames == nil {
				gotNames = []string{}
			}

			require.Equal(t, tt.wantNames, gotNames)
		})
	}
}

func TestFormatCriteria(t *testing.T) {
	tests := []struct {
		name      string
		detectors []capabilities.Detector
		want      string
	}{
		{
			name: "glob method - no parenthetical",
			detectors: []capabilities.Detector{
				{
					Method:   capabilities.GlobDetection,
					Criteria: []string{"**/*.jar", "**/*.war"},
				},
			},
			want: "**/*.jar, **/*.war",
		},
		{
			name: "path method - with parenthetical",
			detectors: []capabilities.Detector{
				{
					Method:   capabilities.PathDetection,
					Criteria: []string{"/usr/bin/python"},
				},
			},
			want: "/usr/bin/python (path)",
		},
		{
			name: "mimetype method - with parenthetical",
			detectors: []capabilities.Detector{
				{
					Method:   capabilities.MIMETypeDetection,
					Criteria: []string{"application/x-executable"},
				},
			},
			want: "application/x-executable (mimetype)",
		},
		{
			name: "multiple criteria with non-glob method",
			detectors: []capabilities.Detector{
				{
					Method:   capabilities.PathDetection,
					Criteria: []string{"/bin/sh", "/bin/bash"},
				},
			},
			want: "/bin/sh, /bin/bash (path)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCriteria(tt.detectors)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFormatBool(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name  string
		input *bool
		want  string
	}{
		{
			name:  "true renders check mark",
			input: &trueVal,
			want:  "✔",
		},
		{
			name:  "false renders dot",
			input: &falseVal,
			want:  "·",
		},
		{
			name:  "nil renders dash",
			input: nil,
			want:  "-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatBool(tt.input)
			// strip any styling to check the core character
			require.Contains(t, got, tt.want)
		})
	}
}

func TestFormatStringSlice(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  string
	}{
		{
			name:  "empty slice",
			input: []string{},
			want:  "",
		},
		{
			name:  "single item",
			input: []string{"direct"},
			want:  "direct",
		},
		{
			name:  "multiple items",
			input: []string{"direct", "indirect"},
			want:  "direct, indirect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatStringSlice(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestBuildTableRow(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name          string
		catalogerName string
		selectors     string
		capability    *capabilities.Capability
		wantContains  []string
	}{
		{
			name:          "nil capability shows defaults",
			catalogerName: "test-cataloger",
			selectors:     "**/*.txt",
			capability:    nil,
			wantContains:  []string{"test-cataloger", "**/*.txt", "-"},
		},
		{
			name:          "capability with all fields",
			catalogerName: "python-cataloger",
			selectors:     "**/setup.py",
			capability: &capabilities.Capability{
				License: &trueVal,
				Dependencies: &capabilities.DependencyCapabilities{
					Depth: []string{"direct", "indirect"},
					Edges: "complete",
					Kinds: []string{"runtime", "dev"},
				},
				PackageManager: &capabilities.PackageManagerCapabilities{
					Files: &capabilities.FileCapabilities{
						Listing: &trueVal,
						Digests: &trueVal,
					},
					PackageIntegrityHash: &trueVal,
				},
			},
			wantContains: []string{
				"python-cataloger",
				"**/setup.py",
				"✔",
				"complete",
				"runtime, dev",
			},
		},
		{
			name:          "capability with partial fields",
			catalogerName: "minimal-cataloger",
			selectors:     "N/A",
			capability: &capabilities.Capability{
				License: &falseVal,
				Dependencies: &capabilities.DependencyCapabilities{
					Depth: []string{"direct"},
					Edges: "flat",
					Kinds: []string{},
				},
				PackageManager: &capabilities.PackageManagerCapabilities{
					Files: &capabilities.FileCapabilities{
						Listing: &falseVal,
						Digests: &falseVal,
					},
					PackageIntegrityHash: &falseVal,
				},
			},
			wantContains: []string{
				"minimal-cataloger",
				"N/A",
				"direct",
				"flat",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := buildTableRow("test-ecosystem", tt.catalogerName, tt.selectors, tt.capability)

			// convert row to string representation for checking
			var rowStr strings.Builder
			for _, cell := range row {
				rowStr.WriteString(cell)
				rowStr.WriteString(" ")
			}

			for _, want := range tt.wantContains {
				require.Contains(t, rowStr.String(), want)
			}
		})
	}
}

func TestRenderCatalogerInfoJSON(t *testing.T) {
	trueVal := true
	falseVal := false

	catalogers := []capabilities.CatalogerEntry{
		{
			Ecosystem: "test",
			Name:      "test-generic-cataloger",
			Type:      "generic",
			Parsers: []capabilities.Parser{
				{
					ParserFunction: "parseTest",
					Detector: capabilities.Detector{
						Method:   capabilities.GlobDetection,
						Criteria: []string{"**/*.test"},
					},
					Capabilities: map[capabilities.EnrichmentMode]*capabilities.Capability{
						capabilities.OfflineMode: {
							License: &trueVal,
							Dependencies: &capabilities.DependencyCapabilities{
								Depth: []string{"direct"},
								Edges: "flat",
								Kinds: []string{"runtime"},
							},
							PackageManager: &capabilities.PackageManagerCapabilities{
								Files: &capabilities.FileCapabilities{
									Listing: &trueVal,
									Digests: &trueVal,
								},
								PackageIntegrityHash: &falseVal,
							},
						},
					},
				},
			},
		},
		{
			Ecosystem: "test",
			Name:      "test-custom-cataloger",
			Type:      "custom",
			Capabilities: map[capabilities.EnrichmentMode]*capabilities.Capability{
				capabilities.OfflineMode: {
					License: &falseVal,
					Dependencies: &capabilities.DependencyCapabilities{
						Depth: []string{},
						Edges: "",
						Kinds: []string{},
					},
					PackageManager: &capabilities.PackageManagerCapabilities{
						Files: &capabilities.FileCapabilities{
							Listing: &falseVal,
							Digests: &falseVal,
						},
						PackageIntegrityHash: &falseVal,
					},
				},
			},
		},
	}

	tests := []struct {
		name    string
		mode    capabilities.EnrichmentMode
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "offline mode",
			mode: capabilities.OfflineMode,
		},
		{
			name: "online mode with no capabilities",
			mode: capabilities.OnlineMode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			doc := &capabilities.Document{
				Catalogers: catalogers,
			}

			got, err := renderCatalogerInfoJSON(doc, catalogers, tt.mode)
			tt.wantErr(t, err)

			if err != nil {
				return
			}

			// verify it's valid JSON
			var result map[string]interface{}
			err = json.Unmarshal([]byte(got), &result)
			require.NoError(t, err)

			// verify structure
			require.Contains(t, result, "mode")
			require.Contains(t, result, "catalogers")
			require.Equal(t, string(tt.mode), result["mode"])

			// verify capability_format field is present
			catalogersList := result["catalogers"].([]interface{})
			require.Greater(t, len(catalogersList), 0)

			for _, cat := range catalogersList {
				catMap := cat.(map[string]interface{})
				require.Contains(t, catMap, "capability_format")
			}
		})
	}
}

func TestRenderCatalogerInfoJSONWithV2Capabilities(t *testing.T) {
	// test cataloger with capabilities-v2
	catalogers := []capabilities.CatalogerEntry{
		{
			Ecosystem: "test",
			Name:      "test-v2-cataloger",
			Type:      "custom",
			CapabilitiesV2: capabilities.CapabilitySet{
				{
					Name:    "license",
					Default: false,
					Conditions: []capabilities.CapabilityCondition{
						{
							When:    map[string]interface{}{"SearchRemoteLicenses": true},
							Value:   true,
							Comment: "License info fetched from registry",
						},
					},
				},
				{
					Name:    "dependency.depth",
					Default: []string{"direct", "indirect"},
				},
			},
		},
	}

	doc := &capabilities.Document{
		Catalogers: catalogers,
	}

	got, err := renderCatalogerInfoJSON(doc, catalogers, capabilities.OfflineMode)
	require.NoError(t, err)

	// verify it's valid JSON
	var result map[string]interface{}
	err = json.Unmarshal([]byte(got), &result)
	require.NoError(t, err)

	// verify structure includes capabilities_v2
	catalogersList := result["catalogers"].([]interface{})
	require.Len(t, catalogersList, 1)

	cat := catalogersList[0].(map[string]interface{})
	require.Equal(t, "v2", cat["capability_format"])
	require.Contains(t, cat, "capabilities_v2")

	// verify capabilities_v2 structure
	capsV2 := cat["capabilities_v2"].([]interface{})
	require.Len(t, capsV2, 2)

	// check first capability field
	field1 := capsV2[0].(map[string]interface{})
	require.Equal(t, "license", field1["field"])
	require.Equal(t, false, field1["default"])
	require.Contains(t, field1, "conditions")
}

func TestRenderCatalogerInfoTable(t *testing.T) {
	trueVal := true
	falseVal := false

	catalogers := []capabilities.CatalogerEntry{
		{
			Ecosystem: "test",
			Name:      "test-cataloger",
			Type:      "generic",
			Parsers: []capabilities.Parser{
				{
					ParserFunction: "parseTest",
					Detector: capabilities.Detector{
						Method:   capabilities.GlobDetection,
						Criteria: []string{"**/*.test"},
					},
					Capabilities: map[capabilities.EnrichmentMode]*capabilities.Capability{
						capabilities.OfflineMode: {
							License: &trueVal,
							Dependencies: &capabilities.DependencyCapabilities{
								Depth: []string{"direct"},
								Edges: "flat",
								Kinds: []string{"runtime"},
							},
							PackageManager: &capabilities.PackageManagerCapabilities{
								Files: &capabilities.FileCapabilities{
									Listing: &trueVal,
									Digests: &falseVal,
								},
								PackageIntegrityHash: &falseVal,
							},
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name         string
		catalogers   []capabilities.CatalogerEntry
		mode         capabilities.EnrichmentMode
		wantContains []string
	}{
		{
			name:       "renders table with cataloger data",
			catalogers: catalogers,
			mode:       capabilities.OfflineMode,
			wantContains: []string{
				"test-cataloger",
				"**/*.test",
				"CATALOGER",
				"CRITERIA",
				"LICENSE",
				"DEPTH",
				"LISTING",
			},
		},
		{
			name:       "empty catalogers list",
			catalogers: []capabilities.CatalogerEntry{},
			mode:       capabilities.OfflineMode,
			wantContains: []string{
				"No catalogers found",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := &capabilities.Document{
				Catalogers: tt.catalogers,
			}

			got := renderCatalogerInfoTable(doc, tt.catalogers, tt.mode)

			for _, want := range tt.wantContains {
				require.Contains(t, got, want)
			}
		})
	}
}

func TestRenderCatalogerInfoTableWithV2Capabilities(t *testing.T) {
	// test cataloger with capabilities-v2
	catalogers := []capabilities.CatalogerEntry{
		{
			Ecosystem: "javascript",
			Name:      "npm-cataloger",
			Type:      "custom",
			Config:    "javascript.CatalogerConfig",
			CapabilitiesV2: capabilities.CapabilitySet{
				{
					Name:    "license",
					Default: false,
					Conditions: []capabilities.CapabilityCondition{
						{
							When:    map[string]interface{}{"SearchRemoteLicenses": true},
							Value:   true,
							Comment: "License info fetched from NPM registry",
						},
					},
				},
				{
					Name:    "dependency.depth",
					Default: []string{"direct", "indirect"},
				},
			},
		},
	}

	doc := &capabilities.Document{
		Catalogers: catalogers,
	}

	got := renderCatalogerInfoTable(doc, catalogers, capabilities.OfflineMode)

	// should include v2 capabilities section
	require.Contains(t, got, "Configuration Impact on Capabilities")
	require.Contains(t, got, "npm-cataloger")
	require.Contains(t, got, "license")
	require.Contains(t, got, "Default: false")
	require.Contains(t, got, "When SearchRemoteLicenses=true: true")
	require.Contains(t, got, "License info fetched from NPM registry")
	require.Contains(t, got, "dependency.depth")
	require.Contains(t, got, "[direct, indirect]")
}

func TestFormatCapabilityValue(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  string
	}{
		{
			name:  "nil value",
			input: nil,
			want:  "null",
		},
		{
			name:  "bool true",
			input: true,
			want:  "true",
		},
		{
			name:  "bool false",
			input: false,
			want:  "false",
		},
		{
			name:  "string value",
			input: "test-value",
			want:  "test-value",
		},
		{
			name:  "string slice",
			input: []string{"direct", "indirect"},
			want:  "[direct, indirect]",
		},
		{
			name:  "interface slice",
			input: []interface{}{"runtime", "dev"},
			want:  "[runtime, dev]",
		},
		{
			name:  "empty slice",
			input: []string{},
			want:  "[]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCapabilityValue(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFormatWhenClause(t *testing.T) {
	tests := []struct {
		name  string
		input map[string]interface{}
		want  string
	}{
		{
			name:  "empty when clause",
			input: map[string]interface{}{},
			want:  "always",
		},
		{
			name: "single condition",
			input: map[string]interface{}{
				"SearchRemoteLicenses": true,
			},
			want: "SearchRemoteLicenses=true",
		},
		{
			name: "multiple conditions",
			input: map[string]interface{}{
				"SearchRemoteLicenses": true,
				"UseNetwork":           true,
			},
			// note: order may vary, but should contain both with AND
			want: " AND ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatWhenClause(tt.input)
			if strings.Contains(tt.want, " AND ") {
				// for multiple conditions, just check it contains AND
				require.Contains(t, got, " AND ")
				require.Contains(t, got, "SearchRemoteLicenses=true")
				require.Contains(t, got, "UseNetwork=true")
			} else {
				require.Equal(t, tt.want, got)
			}
		})
	}
}
