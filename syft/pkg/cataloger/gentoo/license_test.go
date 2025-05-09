package gentoo

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// you can get a good sense of test fixtures with:
//   docker run --rm -it gentoo/stage3 bash -c 'find var/db/pkg/ | grep LICENSE | xargs cat'

func Test_extractLicenses(t *testing.T) {

	tests := []struct {
		name           string
		license        string
		wantExpression string
	}{
		{
			name:           "empty",
			license:        "",
			wantExpression: "",
		},
		{
			name:           "single",
			license:        "GPL-2",
			wantExpression: "GPL-2",
		},
		{
			name:           "multiple",
			license:        "GPL-2 GPL-3 ", // note the extra space
			wantExpression: "GPL-2 AND GPL-3",
		},
		{
			name:           "license choices",
			license:        "|| ( GPL-2 GPL-3 )\n", // note the newline
			wantExpression: "GPL-2 OR GPL-3",
		},
		{
			// this might not be correct behavior, but we do our best with missing info
			name:           "license choices with missing useflag suffix",
			license:        "GPL-3+ LGPL-3+ || ( GPL-3+ libgcc libstdc++ gcc-runtime-library-exception-3.1 ) FDL-1.3+",                // no use flag so what do we do with FDL here?
			wantExpression: "GPL-3+ AND LGPL-3+ AND (GPL-3+ OR libgcc OR libstdc++ OR gcc-runtime-library-exception-3.1 OR FDL-1.3+)", // "OR FDL-1.3+" is probably wrong at the end...
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, expression := extractLicenses(nil, nil, strings.NewReader(tt.license))
			assert.Equalf(t, tt.wantExpression, expression, "unexpected expression for %v", tt.license)
			assert.Equalf(t, strings.TrimSpace(tt.license), raw, "unexpected raw for %v", tt.license)
		})
	}
}

func TestParseLicenseGroups(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    map[string][]string
		expectError require.ErrorAssertionFunc
	}{
		{
			name:  "basic nesting example",
			input: "test-fixtures/license-groups/example1",
			expected: map[string][]string{
				"FSF-APPROVED": {
					"Apache-2.0", "BSD", "BSD-2", "GPL-2", "GPL-3", "LGPL-2.1", "LGPL-3", "X11", "ZLIB",
					"Apache-1.1", "BSD-4", "MPL-1.0", "MPL-1.1", "PSF-2.0",
				},
				"GPL-COMPATIBLE": {
					"Apache-2.0", "BSD", "BSD-2", "GPL-2", "GPL-3", "LGPL-2.1", "LGPL-3", "X11", "ZLIB",
				},
			},
		},
		{
			name:        "error on cycles",
			input:       "test-fixtures/license-groups/cycle",
			expectError: require.Error,
		},
		{
			name:        "error on self references",
			input:       "test-fixtures/license-groups/self",
			expectError: require.Error,
		},
		{
			name:        "error on missing reference",
			input:       "test-fixtures/license-groups/missing",
			expectError: require.Error,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.expectError == nil {
				tc.expectError = require.NoError
			}

			contents, err := os.ReadFile(tc.input)
			require.NoError(t, err)

			actual, err := parseLicenseGroups(bytes.NewReader(contents))
			tc.expectError(t, err)
			if err != nil {
				return
			}

			if d := cmp.Diff(tc.expected, actual); d != "" {
				t.Errorf("unexpected license groups (-want +got):\n%s", d)
			}
		})
	}
}

func TestReplaceLicenseGroups(t *testing.T) {
	tests := []struct {
		name     string
		licenses []string
		groups   map[string][]string
		expected []string
	}{
		{
			name:     "nil groups",
			licenses: []string{"MIT", "Apache-2.0", "@GPL"},
			groups:   nil,
			expected: []string{"MIT", "Apache-2.0", "@GPL"},
		},
		{
			name:     "empty groups",
			licenses: []string{"MIT", "Apache-2.0", "@GPL"},
			groups:   map[string][]string{},
			expected: []string{"MIT", "Apache-2.0", "@GPL"},
		},
		{
			name:     "no group references",
			licenses: []string{"MIT", "Apache-2.0", "GPL-2.0"},
			groups:   map[string][]string{"GPL": {"GPL-2.0", "GPL-3.0"}},
			expected: []string{"MIT", "Apache-2.0", "GPL-2.0"},
		},
		{
			name:     "single group reference",
			licenses: []string{"MIT", "@GPL", "Apache-2.0"},
			groups:   map[string][]string{"GPL": {"GPL-2.0", "GPL-3.0"}},
			expected: []string{"MIT", "GPL-2.0", "GPL-3.0", "Apache-2.0"},
		},
		{
			name:     "multiple group references",
			licenses: []string{"@MIT-LIKE", "@GPL", "BSD-3"},
			groups: map[string][]string{
				"MIT-LIKE": {"MIT", "ISC"},
				"GPL":      {"GPL-2.0", "GPL-3.0"},
			},
			expected: []string{"MIT", "ISC", "GPL-2.0", "GPL-3.0", "BSD-3"},
		},
		{
			name:     "unknown group reference",
			licenses: []string{"MIT", "@UNKNOWN", "Apache-2.0"},
			groups:   map[string][]string{"GPL": {"GPL-2.0", "GPL-3.0"}},
			expected: []string{"MIT", "@UNKNOWN", "Apache-2.0"},
		},
		{
			name:     "reference at end",
			licenses: []string{"MIT", "Apache-2.0", "@GPL"},
			groups:   map[string][]string{"GPL": {"GPL-2.0", "GPL-3.0"}},
			expected: []string{"MIT", "Apache-2.0", "GPL-2.0", "GPL-3.0"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inputLicenses := make([]string, len(tc.licenses))
			copy(inputLicenses, tc.licenses)

			actual := replaceLicenseGroups(inputLicenses, tc.groups)

			assert.Equal(t, tc.expected, actual)
		})
	}
}
