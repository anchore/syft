package options

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_fileSource_PostLoad(t *testing.T) {
	tests := []struct {
		name    string
		cfg     fileSource
		assert  func(t *testing.T, cfg fileSource)
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "deduplicate digests",
			cfg: fileSource{
				Digests: []string{"sha1", "sha1"},
			},
			assert: func(t *testing.T, cfg fileSource) {
				assert.Equal(t, []string{"sha1"}, cfg.Digests)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}
			tt.wantErr(t, tt.cfg.PostLoad())
			if tt.assert != nil {
				tt.assert(t, tt.cfg)
			}
		})
	}
}

func Test_imageSource_perFileReadLimit(t *testing.T) {
	tests := []struct {
		name    string
		cfg     imageSource
		want    int64
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "unset means no limit",
			cfg:  imageSource{},
			want: math.MaxInt64,
		},
		{
			name: "zero means no limit",
			cfg:  imageSource{MaxLayerSize: "0"},
			want: math.MaxInt64,
		},
		{
			name: "user provided limit is honored",
			cfg:  imageSource{MaxLayerSize: "500MB"},
			want: 500 * 1000 * 1000,
		},
		{
			name: "limits beyond int64 are clamped",
			cfg:  imageSource{MaxLayerSize: "10EB"},
			want: math.MaxInt64,
		},
		{
			name:    "invalid limit is an error",
			cfg:     imageSource{MaxLayerSize: "not-a-size"},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}
			got, err := tt.cfg.perFileReadLimit()
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			require.Equal(t, tt.want, got)
		})
	}
}
