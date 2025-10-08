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
		name     string
		criteria []string
		method   capabilities.ArtifactDetectionMethod
		want     string
	}{
		{
			name:     "glob method - no parenthetical",
			criteria: []string{"**/*.jar", "**/*.war"},
			method:   capabilities.GlobDetection,
			want:     "**/*.jar, **/*.war",
		},
		{
			name:     "path method - with parenthetical",
			criteria: []string{"/usr/bin/python"},
			method:   capabilities.PathDetection,
			want:     "/usr/bin/python (path)",
		},
		{
			name:     "mimetype method - with parenthetical",
			criteria: []string{"application/x-executable"},
			method:   capabilities.MIMETypeDetection,
			want:     "application/x-executable (mimetype)",
		},
		{
			name:     "multiple criteria with non-glob method",
			criteria: []string{"/bin/sh", "/bin/bash"},
			method:   capabilities.PathDetection,
			want:     "/bin/sh, /bin/bash (path)",
		},
		{
			name:     "more than 3 criteria - splits with newline",
			criteria: []string{"a", "b", "c", "d"},
			method:   capabilities.GlobDetection,
			want:     "a, b, c\nd",
		},
		{
			name:     "exactly 6 criteria - splits into 2 lines",
			criteria: []string{"a", "b", "c", "d", "e", "f"},
			method:   capabilities.GlobDetection,
			want:     "a, b, c\nd, e, f",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCriteria(tt.criteria, tt.method)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFormatBool(t *testing.T) {
	tests := []struct {
		name  string
		input bool
		want  string
	}{
		{
			name:  "true renders check mark",
			input: true,
			want:  "✔",
		},
		{
			name:  "false renders dash",
			input: false,
			want:  "·",
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
				License: true,
				Dependencies: capabilities.DependencyCapabilities{
					Reach:    []string{"direct", "indirect"},
					Topology: "complete",
					Kinds:    []string{"runtime", "dev"},
				},
				PackageManager: capabilities.PackageManagerCapabilities{
					Files: capabilities.FileCapabilities{
						Listing: true,
						Digests: true,
					},
					PackageIntegrityHash: true,
				},
			},
			wantContains: []string{
				"python-cataloger",
				"**/setup.py",
				"✔",
				"direct, indirect",
				"complete",
				"runtime, dev",
			},
		},
		{
			name:          "capability with partial fields",
			catalogerName: "minimal-cataloger",
			selectors:     "N/A",
			capability: &capabilities.Capability{
				License: false,
				Dependencies: capabilities.DependencyCapabilities{
					Reach:    []string{"direct"},
					Topology: "flat",
					Kinds:    []string{},
				},
				PackageManager: capabilities.PackageManagerCapabilities{
					Files: capabilities.FileCapabilities{
						Listing: false,
						Digests: false,
					},
					PackageIntegrityHash: false,
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
	catalogers := []capabilities.CatalogerEntry{
		{
			Ecosystem: "test",
			Name:      "test-generic-cataloger",
			Type:      "generic",
			Patterns: []capabilities.Pattern{
				{
					ParserFunction: "parseTest",
					Method:         capabilities.GlobDetection,
					Criteria:       []string{"**/*.test"},
					Capabilities: map[capabilities.EnrichmentMode]*capabilities.Capability{
						capabilities.OfflineMode: {
							License: true,
							Dependencies: capabilities.DependencyCapabilities{
								Reach:    []string{"direct"},
								Topology: "flat",
								Kinds:    []string{"runtime"},
							},
							PackageManager: capabilities.PackageManagerCapabilities{
								Files: capabilities.FileCapabilities{
									Listing: true,
									Digests: true,
								},
								PackageIntegrityHash: false,
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
					License: false,
					Dependencies: capabilities.DependencyCapabilities{
						Reach:    []string{},
						Topology: "",
						Kinds:    []string{},
					},
					PackageManager: capabilities.PackageManagerCapabilities{
						Files: capabilities.FileCapabilities{
							Listing: false,
							Digests: false,
						},
						PackageIntegrityHash: false,
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

			got, err := renderCatalogerInfoJSON(catalogers, tt.mode)
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
		})
	}
}

func TestRenderCatalogerInfoTable(t *testing.T) {
	catalogers := []capabilities.CatalogerEntry{
		{
			Ecosystem: "test",
			Name:      "test-cataloger",
			Type:      "generic",
			Patterns: []capabilities.Pattern{
				{
					ParserFunction: "parseTest",
					Method:         capabilities.GlobDetection,
					Criteria:       []string{"**/*.test"},
					Capabilities: map[capabilities.EnrichmentMode]*capabilities.Capability{
						capabilities.OfflineMode: {
							License: true,
							Dependencies: capabilities.DependencyCapabilities{
								Reach:    []string{"direct"},
								Topology: "flat",
								Kinds:    []string{"runtime"},
							},
							PackageManager: capabilities.PackageManagerCapabilities{
								Files: capabilities.FileCapabilities{
									Listing: true,
									Digests: false,
								},
								PackageIntegrityHash: false,
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
				"REACH",
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
			got := renderCatalogerInfoTable(tt.catalogers, tt.mode)

			for _, want := range tt.wantContains {
				require.Contains(t, got, want)
			}
		})
	}
}
