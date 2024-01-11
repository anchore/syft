package filecataloging

import (
	"crypto"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func TestConfig_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		want    []byte
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "converts hashers to strings",
			cfg: Config{
				Selection: file.FilesOwnedByPackageSelection,
				Hashers:   []crypto.Hash{crypto.SHA256},
			},
			want: []byte(`{"selection":"owned-by-package","hashers":["sha-256"],"content":{"globs":null,"skip-files-above-size":0}}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			got, err := tt.cfg.MarshalJSON()
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			if d := cmp.Diff(got, tt.want); d != "" {
				t.Errorf("MarshalJSON() mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func TestConfig_UnmarshalJSON(t *testing.T) {

	tests := []struct {
		name    string
		data    []byte
		want    Config
		wantErr bool
	}{
		{
			name: "converts strings to hashers",
			data: []byte(`{"selection":"owned-by-package","hashers":["sha-256"]}`),
			want: Config{
				Selection: file.FilesOwnedByPackageSelection,
				Hashers:   []crypto.Hash{crypto.SHA256},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{}
			if err := cfg.UnmarshalJSON(tt.data); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}

			assert.Equal(t, tt.want, cfg)
		})
	}
}
