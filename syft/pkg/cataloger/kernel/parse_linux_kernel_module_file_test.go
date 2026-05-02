package kernel

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"
)

func TestOpenMaybeCompressedModule(t *testing.T) {
	const payload = "the elf bytes go here\nbut they don't have to be valid for this test"

	tests := []struct {
		name    string
		path    string
		wrap    func(t *testing.T, plaintext string) []byte
		wantErr bool
	}{
		{
			name: "plain .ko is passed through unchanged",
			path: "/lib/modules/6.12/kernel/foo.ko",
			wrap: func(_ *testing.T, plaintext string) []byte { return []byte(plaintext) },
		},
		{
			name: "xz-compressed .ko.xz is decompressed",
			path: "/lib/modules/6.12/kernel/foo.ko.xz",
			wrap: func(t *testing.T, plaintext string) []byte {
				var buf bytes.Buffer
				w, err := xz.NewWriter(&buf)
				require.NoError(t, err)
				_, err = io.Copy(w, strings.NewReader(plaintext))
				require.NoError(t, err)
				require.NoError(t, w.Close())
				return buf.Bytes()
			},
		},
		{
			name: "gzip-compressed .ko.gz is decompressed",
			path: "/lib/modules/6.12/kernel/foo.ko.gz",
			wrap: func(t *testing.T, plaintext string) []byte {
				var buf bytes.Buffer
				w := gzip.NewWriter(&buf)
				_, err := io.Copy(w, strings.NewReader(plaintext))
				require.NoError(t, err)
				require.NoError(t, w.Close())
				return buf.Bytes()
			},
		},
		{
			name: "zstd-compressed .ko.zst is decompressed",
			path: "/lib/modules/6.12/kernel/foo.ko.zst",
			wrap: func(t *testing.T, plaintext string) []byte { return zstdEncode(t, plaintext) },
		},
		{
			name: "garbage in .ko.xz returns an error",
			path: "/lib/modules/6.12/kernel/foo.ko.xz",
			wrap: func(_ *testing.T, _ string) []byte {
				return []byte("not really xz")
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.wrap(t, payload)
			rc := io.NopCloser(bytes.NewReader(body))

			out, err := openMaybeCompressedModule(tc.path, rc)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })

			got, err := io.ReadAll(out)
			require.NoError(t, err)
			assert.Equal(t, payload, string(got))
		})
	}
}

func zstdEncode(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	require.NoError(t, err)
	_, err = io.Copy(w, strings.NewReader(s))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}
