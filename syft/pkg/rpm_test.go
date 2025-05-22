package pkg

import (
	"strings"
	"testing"

	"github.com/go-test/deep"
	"github.com/stretchr/testify/assert"
)

func TestRpmMetadata_FileOwner(t *testing.T) {
	tests := []struct {
		metadata RpmDBEntry
		expected []string
	}{
		{
			metadata: RpmDBEntry{
				Files: []RpmFileRecord{
					{Path: "/somewhere"},
					{Path: "/else"},
				},
			},
			expected: []string{
				"/else",
				"/somewhere",
			},
		},
		{
			metadata: RpmDBEntry{
				Files: []RpmFileRecord{
					{Path: "/somewhere"},
					{Path: ""},
				},
			},
			expected: []string{
				"/somewhere",
			},
		},
	}

	for _, test := range tests {
		t.Run(strings.Join(test.expected, ","), func(t *testing.T) {
			actual := test.metadata.OwnedFiles()
			for _, d := range deep.Equal(test.expected, actual) {
				t.Errorf("diff: %+v", d)
			}
		})
	}
}

func TestRpmSignature_String(t *testing.T) {
	tests := []struct {
		name      string
		signature RpmSignature
		expected  string
	}{
		{
			name: "standard signature",
			signature: RpmSignature{
				PublicKeyAlgorithm: "RSA",
				HashAlgorithm:      "SHA256",
				Created:            "Mon May 16 12:32:55 2022",
				IssuerKeyID:        "702d426d350d275d",
			},
			expected: "RSA/SHA256, Mon May 16 12:32:55 2022, Key ID 702d426d350d275d",
		},
		{
			name: "empty fields",
			signature: RpmSignature{
				PublicKeyAlgorithm: "",
				HashAlgorithm:      "",
				Created:            "",
				IssuerKeyID:        "",
			},
			expected: "",
		},
		{
			name: "partial empty fields",
			signature: RpmSignature{
				PublicKeyAlgorithm: "RSA",
				HashAlgorithm:      "",
				Created:            "Mon May 16 12:32:55 2022",
				IssuerKeyID:        "",
			},
			expected: "RSA/, Mon May 16 12:32:55 2022, Key ID ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.signature.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}
