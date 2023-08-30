package file

import (
	"crypto"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func TestCleanDigestAlgorithmName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "go case",
			input: "SHA-256",
			want:  "sha256",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, CleanDigestAlgorithmName(tt.input))
		})
	}
}

func TestNewDigestsFromFile(t *testing.T) {
	require.NotEmpty(t, supportedHashAlgorithms())

	tests := []struct {
		name    string
		fixture string
		hashes  []crypto.Hash
		want    []file.Digest
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "check supported hash algorithms",
			fixture: "test-fixtures/digest.txt",
			hashes:  supportedHashAlgorithms(),
			want: []file.Digest{
				{
					Algorithm: "md5",
					Value:     "e8818a24402ae7f8b874cdd9350c1b51",
				},
				{
					Algorithm: "sha1",
					Value:     "eea4671d168c81fd52e615ed9fb3531a526f4748",
				},
				{
					Algorithm: "sha224",
					Value:     "fd993e84c7afb449d34bcae7c5ee118f5c73b50170da05171523b22c",
				},
				{
					Algorithm: "sha256",
					Value:     "cbf1a703b7e4a67529d6e17114880dfa9f879f3749872e1a9d4a20ac509165ad",
				},
				{
					Algorithm: "sha384",
					Value:     "1eaded3f17fb8d7b731c9175a0f355d3a35575c3cb6cdda46a5272b632968d7257a5e6437d0efae599a81a1b2dcc81ba",
				},
				{
					Algorithm: "sha512",
					Value:     "b49d5995456edba144dce750eaa8eae12af8fd08c076d401fcf78aac4172080feb70baaa5ed8c1b05046ec278446330fbf77e8ca9e60c03945ded761a641a7e1",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			fh, err := os.Open(tt.fixture)
			require.NoError(t, err)

			got, err := NewDigestsFromFile(fh, tt.hashes)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHashers(t *testing.T) {
	tests := []struct {
		name    string
		names   []string
		want    []crypto.Hash
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:  "check supported hash algorithms",
			names: []string{"MD-5", "shA1", "sHa224", "sha---256", "sha384", "sha512"},
			want: []crypto.Hash{
				crypto.MD5,
				crypto.SHA1,
				crypto.SHA224,
				crypto.SHA256,
				crypto.SHA384,
				crypto.SHA512,
			},
		},
		{
			name:    "error on unsupported hash algorithm",
			names:   []string{"made-up"},
			wantErr: require.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			got, err := Hashers(tt.names...)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
