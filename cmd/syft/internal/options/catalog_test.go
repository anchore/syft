package options

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCatalog_PostLoad(t *testing.T) {

	tests := []struct {
		name    string
		options Catalog
		assert  func(t *testing.T, options Catalog)
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "mutually exclusive cataloger flags (cat / def-cat)",
			options: Catalog{
				Catalogers:        []string{"foo,bar", "42"},
				DefaultCatalogers: []string{"some,thing"},
				Scope:             "squashed",
			},
			wantErr: assert.Error,
		},
		{
			name: "mutually exclusive cataloger flags (cat / sel-cat)",
			options: Catalog{
				Catalogers:       []string{"foo,bar", "42"},
				SelectCatalogers: []string{"some,thing"},
				Scope:            "squashed",
			},
			wantErr: assert.Error,
		},
		{
			name: "allow old cataloger flags",
			options: Catalog{
				Catalogers: []string{"foo,bar"},
				Scope:      "squashed",
			},
			assert: func(t *testing.T, options Catalog) {
				assert.Equal(t, []string{"bar", "foo"}, options.DefaultCatalogers) // note: sorted order
				assert.Equal(t, []string{"bar", "foo"}, options.Catalogers)        // note: sorted order
			},
		},
		{
			name: "allow new cataloger flags",
			options: Catalog{
				SelectCatalogers:  []string{"foo,bar", "42"},
				DefaultCatalogers: []string{"some,thing"},
				Scope:             "squashed",
			},
			assert: func(t *testing.T, options Catalog) {
				assert.Equal(t, []string{"42", "bar", "foo"}, options.SelectCatalogers) // note: sorted order
				assert.Equal(t, []string{"some", "thing"}, options.DefaultCatalogers)   // note: sorted order
				assert.Empty(t, options.Catalogers)
			},
		},
		{
			name: "must have package overlap flag when pruning binaries by overlap",
			options: Catalog{
				Package:       packageConfig{ExcludeBinaryOverlapByOwnership: true},
				Relationships: relationshipsConfig{PackageFileOwnershipOverlap: false},
			},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}
			tt.wantErr(t, tt.options.PostLoad(), fmt.Sprintf("PostLoad()"))
			if tt.assert != nil {
				tt.assert(t, tt.options)
			}
		})
	}
}

func Test_enrichmentEnabled(t *testing.T) {
	tests := []struct {
		directives string
		test       string
		expected   *bool
	}{
		{
			directives: "",
			test:       "java",
			expected:   nil,
		},
		{
			directives: "none",
			test:       "java",
			expected:   ptr(false),
		},
		{
			directives: "none,+java",
			test:       "java",
			expected:   ptr(true),
		},
		{
			directives: "all,none",
			test:       "java",
			expected:   ptr(false),
		},
		{
			directives: "all",
			test:       "java",
			expected:   ptr(true),
		},
		{
			directives: "golang,js",
			test:       "java",
			expected:   nil,
		},
		{
			directives: "golang,-js,java",
			test:       "java",
			expected:   ptr(true),
		},
		{
			directives: "golang,js,-java",
			test:       "java",
			expected:   ptr(false),
		},
		{
			directives: "all",
			test:       "java",
			expected:   ptr(true),
		},
		{
			directives: "all,-java",
			test:       "java",
			expected:   ptr(false),
		},
	}

	for _, test := range tests {
		t.Run(test.directives, func(t *testing.T) {
			got := enrichmentEnabled(Flatten([]string{test.directives}), test.test)
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestCatalog_ParseSBOMProperties(t *testing.T) {
	tests := []struct {
		name       string
		properties []string
		expected   map[string]string
	}{
		{
			name:       "empty properties",
			properties: []string{},
			expected:   map[string]string{},
		},
		{
			name:       "nil properties",
			properties: nil,
			expected:   map[string]string{},
		},
		{
			name:       "single property",
			properties: []string{"environment=production"},
			expected: map[string]string{
				"environment": "production",
			},
		},
		{
			name:       "multiple properties",
			properties: []string{"environment=production", "team=security", "version=1.0.0"},
			expected: map[string]string{
				"environment": "production",
				"team":        "security",
				"version":     "1.0.0",
			},
		},
		{
			name:       "property with equals in value",
			properties: []string{"url=https://example.com?param=value"},
			expected: map[string]string{
				"url": "https://example.com?param=value",
			},
		},
		{
			name:       "property without equals (ignored)",
			properties: []string{"invalidproperty", "valid=value"},
			expected: map[string]string{
				"valid": "value",
			},
		},
		{
			name:       "property with empty value",
			properties: []string{"empty=", "filled=value"},
			expected: map[string]string{
				"empty":  "",
				"filled": "value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			catalog := Catalog{
				SBOMProperties: tt.properties,
			}

			result := catalog.ParseSBOMProperties()
			assert.Equal(t, tt.expected, result)
		})
	}
}
