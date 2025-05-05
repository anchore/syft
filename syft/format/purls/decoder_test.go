package purls

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/cmptest"
	"github.com/anchore/syft/syft/pkg"
)

func TestDecoder_Decode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []pkg.Package
	}{
		{
			name:  "basic",
			input: `pkg:generic/some-package@1.2.3`,
			expected: []pkg.Package{
				{
					Name:    "some-package",
					Type:    pkg.UnknownPkg,
					Version: "1.2.3",
					PURL:    "pkg:generic/some-package@1.2.3",
				},
			},
		},
		{
			name:  "npm",
			input: `pkg:npm/some-package@1.2.3`,
			expected: []pkg.Package{
				{
					Name:     "some-package",
					Type:     pkg.NpmPkg,
					Language: pkg.JavaScript,
					Version:  "1.2.3",
					PURL:     "pkg:npm/some-package@1.2.3",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dec := NewFormatDecoder()
			got, _, _, err := dec.Decode(strings.NewReader(test.input))
			require.NoError(t, err)

			if diff := cmp.Diff(test.expected, got.Artifacts.Packages.Sorted(), cmptest.DefaultOptions()...); diff != "" {
				t.Errorf("expected packages (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_DecodeEncodeCycle(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "basic",
			input: "pkg:generic/some-package@1.2.3",
		},
		{
			name:  "multiple",
			input: "pkg:generic/pkg1\npkg:generic/pkg2\n\npkg:npm/@vercel/ncc@2.9.5",
		},
		{
			name:  "java",
			input: "pkg:maven/org.apache/some-thing@4.11.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := NewFormatDecoder()
			decodedSBOM, _, _, err := dec.Decode(strings.NewReader(tt.input))
			require.NoError(t, err)

			var buf bytes.Buffer
			enc := NewFormatEncoder()
			require.NoError(t, enc.Encode(&buf, *decodedSBOM))

			in := strings.TrimSpace(regexp.MustCompile(`\s+`).ReplaceAllString(tt.input, "\n"))
			parts := strings.Split(in, "\n")
			slices.Sort(parts)
			in = strings.Join(parts, "\n")

			parts = strings.Split(strings.TrimSpace(buf.String()), "\n")
			slices.Sort(parts)
			got := strings.Join(parts, "\n")
			require.Equal(t, in, got)
		})
	}
}
