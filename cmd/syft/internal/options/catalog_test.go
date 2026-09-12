package options

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCatalog_PostLoad(t *testing.T) {
	tests := []struct {
		name    string
		options Catalog
		assert  func(t *testing.T, options Catalog)
		wantErr assert.ErrorAssertionFunc
	}{
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

// TestCatalog_PostLoad_GOMAXPROCS verifies that Catalog.PostLoad aligns GOMAXPROCS with the configured
// parallelism from the CLI path only, lowering it when appropriate and never raising it. See issue #3924.
func TestCatalog_PostLoad_GOMAXPROCS(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	t.Cleanup(func() {
		runtime.GOMAXPROCS(original)
	})

	tests := []struct {
		name        string
		startProcs  int
		parallelism int
		wantProcs   int
	}{
		{
			name:        "default parallelism leaves GOMAXPROCS alone",
			startProcs:  4,
			parallelism: 0,
			wantProcs:   4,
		},
		{
			name:        "serial parallelism leaves GOMAXPROCS alone",
			startProcs:  4,
			parallelism: 1,
			wantProcs:   4,
		},
		{
			name:        "unbounded parallelism leaves GOMAXPROCS alone",
			startProcs:  4,
			parallelism: -1,
			wantProcs:   4,
		},
		{
			name:        "explicit lower parallelism reduces GOMAXPROCS",
			startProcs:  8,
			parallelism: 2,
			wantProcs:   2,
		},
		{
			name:        "parallelism equal to current GOMAXPROCS is a no-op",
			startProcs:  4,
			parallelism: 4,
			wantProcs:   4,
		},
		{
			name:        "parallelism above current GOMAXPROCS does not raise it",
			startProcs:  2,
			parallelism: 16,
			wantProcs:   2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runtime.GOMAXPROCS(tc.startProcs)

			cfg := Catalog{
				Scope:       "squashed",
				Parallelism: tc.parallelism,
			}
			require.NoError(t, cfg.PostLoad())

			assert.Equal(t, tc.wantProcs, runtime.GOMAXPROCS(0))
		})
	}
}
