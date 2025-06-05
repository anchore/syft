package helpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_encodeHashes(t *testing.T) {
	tests := []struct {
		name string
		pkg  pkg.Package
		want *[]cyclonedx.Hash
	}{
		{
			name: "nil digests",
			pkg:  pkg.Package{Digests: nil},
			want: nil,
		},
		{
			name: "empty digests",
			pkg:  pkg.Package{Digests: []file.Digest{}},
			want: nil,
		},
		{
			name: "unsupported algorithm",
			pkg: pkg.Package{Digests: []file.Digest{
				{Algorithm: "unknown", Value: "abc123"},
			}},
			want: nil,
		},
		{
			name: "single supported algorithm",
			pkg: pkg.Package{Digests: []file.Digest{
				{Algorithm: "sha1", Value: "abc123"},
			}},
			want: &[]cyclonedx.Hash{
				{Algorithm: "SHA-1", Value: "abc123"},
			},
		},
		{
			name: "multiple supported algorithms",
			pkg: pkg.Package{Digests: []file.Digest{
				{Algorithm: "md5", Value: "md5val"},
				{Algorithm: "sha256", Value: "sha256val"},
			}},
			want: &[]cyclonedx.Hash{
				{Algorithm: "MD5", Value: "md5val"},
				{Algorithm: "SHA-256", Value: "sha256val"},
			},
		},
		{
			name: "mixed supported and unsupported algorithms",
			pkg: pkg.Package{Digests: []file.Digest{
				{Algorithm: "md5", Value: "md5val"},
				{Algorithm: "unknown", Value: "xxx"},
			}},
			want: &[]cyclonedx.Hash{
				{Algorithm: "MD5", Value: "md5val"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, encodeHashes(tt.pkg), "encodeHashes(%v)", tt.pkg)
		})
	}
}

func Test_toCycloneDXAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected cyclonedx.HashAlgorithm
	}{
		{
			name:     "valid algorithm name in upper case",
			input:    "SHA1",
			expected: cyclonedx.HashAlgorithm("SHA-1"),
		},
		{
			name:     "valid algorithm name in lower case",
			input:    "sha1",
			expected: cyclonedx.HashAlgorithm("SHA-1"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, toCycloneDXAlgorithm(test.input))
		})
	}
}
