package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
