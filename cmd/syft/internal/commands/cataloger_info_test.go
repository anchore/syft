package commands

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/capabilities"
)

func Test_isDeprecatedCataloger(t *testing.T) {
	tests := []struct {
		name      string
		selectors []string
		want      bool
	}{
		{
			name:      "empty selectors",
			selectors: nil,
			want:      false,
		},
		{
			name:      "no deprecated selector",
			selectors: []string{"python", "pip", "package"},
			want:      false,
		},
		{
			name:      "has deprecated selector",
			selectors: []string{"python", "deprecated", "package"},
			want:      true,
		},
		{
			name:      "only deprecated selector",
			selectors: []string{"deprecated"},
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDeprecatedCataloger(tt.selectors)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_hasBothDirectAndIndirect(t *testing.T) {
	tests := []struct {
		name  string
		items []string
		want  bool
	}{
		{
			name:  "empty slice",
			items: nil,
			want:  false,
		},
		{
			name:  "only direct",
			items: []string{"direct"},
			want:  false,
		},
		{
			name:  "only indirect",
			items: []string{"indirect"},
			want:  false,
		},
		{
			name:  "both direct and indirect",
			items: []string{"direct", "indirect"},
			want:  true,
		},
		{
			name:  "both with other items",
			items: []string{"other", "direct", "more", "indirect", "stuff"},
			want:  true,
		},
		{
			name:  "unrelated items",
			items: []string{"foo", "bar", "baz"},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasBothDirectAndIndirect(tt.items)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_filterCatalogersByName(t *testing.T) {
	catalogers := []capabilities.CatalogerEntry{
		{Name: "python-cataloger", Ecosystem: "python"},
		{Name: "java-cataloger", Ecosystem: "java"},
		{Name: "go-cataloger", Ecosystem: "golang"},
		{Name: "npm-cataloger", Ecosystem: "javascript"},
	}

	tests := []struct {
		name       string
		catalogers []capabilities.CatalogerEntry
		names      []string
		want       []capabilities.CatalogerEntry
	}{
		{
			name:       "empty names returns empty",
			catalogers: catalogers,
			names:      nil,
			want:       nil,
		},
		{
			name:       "single match",
			catalogers: catalogers,
			names:      []string{"python-cataloger"},
			want: []capabilities.CatalogerEntry{
				{Name: "python-cataloger", Ecosystem: "python"},
			},
		},
		{
			name:       "multiple matches",
			catalogers: catalogers,
			names:      []string{"python-cataloger", "java-cataloger"},
			want: []capabilities.CatalogerEntry{
				{Name: "python-cataloger", Ecosystem: "python"},
				{Name: "java-cataloger", Ecosystem: "java"},
			},
		},
		{
			name:       "no matches",
			catalogers: catalogers,
			names:      []string{"nonexistent"},
			want:       nil,
		},
		{
			name:       "partial matches",
			catalogers: catalogers,
			names:      []string{"python-cataloger", "nonexistent"},
			want: []capabilities.CatalogerEntry{
				{Name: "python-cataloger", Ecosystem: "python"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterCatalogersByName(tt.catalogers, tt.names)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("filterCatalogersByName() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_formatCriteria(t *testing.T) {
	tests := []struct {
		name      string
		detectors []capabilities.Detector
		want      string
	}{
		{
			name:      "empty detectors",
			detectors: nil,
			want:      "",
		},
		{
			name: "single glob detector",
			detectors: []capabilities.Detector{
				{
					Method:   capabilities.GlobDetection,
					Criteria: []string{"**/*.py"},
				},
			},
			want: "**/*.py",
		},
		{
			name: "multiple criteria single detector",
			detectors: []capabilities.Detector{
				{
					Method:   capabilities.GlobDetection,
					Criteria: []string{"**/*.py", "**/*.pyc", "**/requirements.txt"},
				},
			},
			want: "**/*.py, **/*.pyc, **/requirements.txt",
		},
		{
			name: "path detection shows method",
			detectors: []capabilities.Detector{
				{
					Method:   capabilities.PathDetection,
					Criteria: []string{"/usr/bin/python"},
				},
			},
			want: "/usr/bin/python (path)",
		},
		{
			name: "mimetype detection shows method",
			detectors: []capabilities.Detector{
				{
					Method:   capabilities.MIMETypeDetection,
					Criteria: []string{"application/x-python"},
				},
			},
			want: "application/x-python (mimetype)",
		},
		{
			name: "multiple detectors combine criteria",
			detectors: []capabilities.Detector{
				{
					Method:   capabilities.GlobDetection,
					Criteria: []string{"**/*.py"},
				},
				{
					Method:   capabilities.GlobDetection,
					Criteria: []string{"**/*.pyc"},
				},
			},
			want: "**/*.py, **/*.pyc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCriteria(tt.detectors)
			assert.Equal(t, tt.want, got)
		})
	}
}

func testDocument() *capabilities.Document {
	return &capabilities.Document{
		Configs: map[string]capabilities.CatalogerConfigEntry{
			"test-config": {
				Fields: []capabilities.CatalogerConfigFieldEntry{
					{Key: "field1", Description: "test field"},
				},
			},
		},
	}
}

func Test_catalogerInfoReport(t *testing.T) {
	tests := []struct {
		name       string
		opts       *catalogerInfoOptions
		doc        *capabilities.Document
		catalogers []capabilities.CatalogerEntry
		wantErr    require.ErrorAssertionFunc
		assertions func(t *testing.T, got string)
	}{
		{
			name: "empty catalogers table",
			opts: &catalogerInfoOptions{Output: "table"},
			doc:  testDocument(),
			assertions: func(t *testing.T, got string) {
				assert.Contains(t, got, "No catalogers found")
			},
		},
		{
			name: "empty catalogers json",
			opts: &catalogerInfoOptions{Output: "json"},
			doc:  testDocument(),
			assertions: func(t *testing.T, got string) {
				assert.Contains(t, got, `"catalogers":null`)
			},
		},
		{
			name: "single cataloger table output",
			opts: &catalogerInfoOptions{Output: "table"},
			doc:  testDocument(),
			catalogers: []capabilities.CatalogerEntry{
				{
					Name:      "test-cataloger",
					Ecosystem: "test",
					Type:      "custom",
					Detectors: []capabilities.Detector{
						{Method: capabilities.GlobDetection, Criteria: []string{"**/*.test"}},
					},
				},
			},
			assertions: func(t *testing.T, got string) {
				assert.Contains(t, got, "test-cataloger")
				assert.Contains(t, got, "ECOSYSTEM")
				assert.Contains(t, got, "CATALOGER")
			},
		},
		{
			name: "single cataloger json output",
			opts: &catalogerInfoOptions{Output: "json"},
			doc:  testDocument(),
			catalogers: []capabilities.CatalogerEntry{
				{
					Name:      "test-cataloger",
					Ecosystem: "test",
					Type:      "custom",
					Selectors: []string{"test", "custom"},
				},
			},
			assertions: func(t *testing.T, got string) {
				assert.Contains(t, got, `"name":"test-cataloger"`)
				assert.Contains(t, got, `"ecosystem":"test"`)
				assert.Contains(t, got, `"type":"custom"`)
			},
		},
		{
			name: "deprecated cataloger json output",
			opts: &catalogerInfoOptions{Output: "json"},
			doc:  testDocument(),
			catalogers: []capabilities.CatalogerEntry{
				{
					Name:      "old-cataloger",
					Ecosystem: "legacy",
					Type:      "custom",
					Selectors: []string{"legacy", "deprecated"},
				},
			},
			assertions: func(t *testing.T, got string) {
				assert.Contains(t, got, `"deprecated":true`)
			},
		},
		{
			name:    "invalid output format",
			opts:    &catalogerInfoOptions{Output: "invalid"},
			doc:     testDocument(),
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			got, err := catalogerInfoReport(tt.opts, tt.doc, tt.catalogers)
			tt.wantErr(t, err)

			if err != nil {
				return
			}

			if tt.assertions != nil {
				tt.assertions(t, got)
			}
		})
	}
}

func Test_formatCriteria_wordWrapping(t *testing.T) {
	// test word wrapping behavior with long criteria lists
	longCriteria := make([]string, 20)
	for i := range longCriteria {
		longCriteria[i] = "**/file" + strings.Repeat("x", 10)
	}

	detector := capabilities.Detector{
		Method:   capabilities.GlobDetection,
		Criteria: longCriteria,
	}

	got := formatCriteria([]capabilities.Detector{detector})

	// should contain newlines for wrapping
	assert.Contains(t, got, "\n")
	// should contain all criteria (joined with ", " and possibly split across lines)
	for _, c := range longCriteria {
		assert.Contains(t, got, c)
	}
}
