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

func TestFlatten(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "preserves order of comma-separated values",
			input:    []string{"registry,docker,oci-dir"},
			expected: []string{"registry", "docker", "oci-dir"},
		},
		{
			name:     "preserves order across multiple entries",
			input:    []string{"registry,docker", "oci-dir"},
			expected: []string{"registry", "docker", "oci-dir"},
		},
		{
			name:     "trims whitespace",
			input:    []string{"  registry  ,  docker  ", "  oci-dir  "},
			expected: []string{"registry", "docker", "oci-dir"},
		},
		{
			name:     "handles single value",
			input:    []string{"registry"},
			expected: []string{"registry"},
		},
		{
			name:     "handles empty input",
			input:    []string{},
			expected: nil,
		},
		{
			name:     "preserves reverse alphabetical order",
			input:    []string{"zebra,yankee,xray"},
			expected: []string{"zebra", "yankee", "xray"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Flatten(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestFlattenAndSort(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "sorts comma-separated values",
			input:    []string{"registry,docker,oci-dir"},
			expected: []string{"docker", "oci-dir", "registry"},
		},
		{
			name:     "sorts across multiple entries",
			input:    []string{"registry,docker", "oci-dir"},
			expected: []string{"docker", "oci-dir", "registry"},
		},
		{
			name:     "trims whitespace and sorts",
			input:    []string{"  registry  ,  docker  ", "  oci-dir  "},
			expected: []string{"docker", "oci-dir", "registry"},
		},
		{
			name:     "handles single value",
			input:    []string{"registry"},
			expected: []string{"registry"},
		},
		{
			name:     "handles empty input",
			input:    []string{},
			expected: nil,
		},
		{
			name:     "sorts reverse alphabetical order",
			input:    []string{"zebra,yankee,xray"},
			expected: []string{"xray", "yankee", "zebra"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FlattenAndSort(tt.input)
			assert.Equal(t, tt.expected, got)
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
			got := enrichmentEnabled(FlattenAndSort([]string{test.directives}), test.test)
			assert.Equal(t, test.expected, got)
		})
	}
}
