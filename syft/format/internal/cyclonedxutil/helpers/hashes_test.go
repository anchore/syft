package helpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_encodeHashes(t *testing.T) {
	type args struct {
		p pkg.Package
	}
	tests := []struct {
		name string
		args args
		want *[]cyclonedx.Hash
	}{
		{
			name: "APK package with checksum",
			args: args{
				p: pkg.Package{
					Metadata: pkg.ApkDBEntry{
						Checksum: "abc123",
					},
				},
			},
			want: &[]cyclonedx.Hash{
				{
					Algorithm: cyclonedx.HashAlgorithm("SHA-256"),
					Value:     "abc123",
				},
			},
		},
		{
			name: "Rust package with checksum",
			args: args{
				p: pkg.Package{
					Metadata: pkg.RustCargoLockEntry{
						Checksum: "def456",
					},
				},
			},
			want: &[]cyclonedx.Hash{
				{
					Algorithm: cyclonedx.HashAlgorithm("SHA-256"),
					Value:     "def456",
				},
			},
		},
		{
			name: "Java package with multiple digests",
			args: args{
				p: pkg.Package{
					Metadata: pkg.JavaArchive{
						ArchiveDigests: []file.Digest{
							{Algorithm: "sha1", Value: "123abc"},
							{Algorithm: "sha256", Value: "456def"},
						},
					},
				},
			},
			want: &[]cyclonedx.Hash{
				{
					Algorithm: cyclonedx.HashAlgorithm("SHA-1"),
					Value:     "123abc",
				},
				{
					Algorithm: cyclonedx.HashAlgorithm("SHA-256"),
					Value:     "456def",
				},
			},
		},
		{
			name: "Package with no metadata",
			args: args{
				p: pkg.Package{},
			},
			want: nil,
		},
		{
			name: "Package with unsupported metadata type",
			args: args{
				p: pkg.Package{
					Metadata: struct{}{}, // Unsupported metadata type
				},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, encodeHashes(tt.args.p), "encodeHashes(%v)", tt.args.p)
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
