package file

import (
	"context"
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
		{
			name:    "empty file has valid checksums",
			fixture: "test-fixtures/empty.txt",
			hashes:  supportedHashAlgorithms(),
			want: []file.Digest{
				{
					Algorithm: "md5",
					Value:     "d41d8cd98f00b204e9800998ecf8427e",
				},
				{
					Algorithm: "sha1",
					Value:     "da39a3ee5e6b4b0d3255bfef95601890afd80709",
				},
				{
					Algorithm: "sha224",
					Value:     "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
				},
				{
					Algorithm: "sha256",
					Value:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				},
				{
					Algorithm: "sha384",
					Value:     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
				},
				{
					Algorithm: "sha512",
					Value:     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
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

			got, err := NewDigestsFromFile(context.TODO(), fh, tt.hashes)
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
