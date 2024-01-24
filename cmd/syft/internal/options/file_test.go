package options

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
)

func Test_fileConfig_PostLoad(t *testing.T) {
	tests := []struct {
		name    string
		cfg     fileConfig
		assert  func(t *testing.T, cfg fileConfig)
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "deduplicate digests",
			cfg: fileConfig{
				Metadata: fileMetadata{
					Selection: file.NoFilesSelection,
					Digests:   []string{"sha1", "sha1"},
				},
			},
			assert: func(t *testing.T, cfg fileConfig) {
				assert.Equal(t, []string{"sha1"}, cfg.Metadata.Digests)
			},
		},
		{
			name: "error on invalid selection",
			cfg: fileConfig{
				Metadata: fileMetadata{
					Selection: file.Selection("invalid"),
				},
			},
			wantErr: assert.Error,
		},
		{
			name:    "error on empty selection",
			cfg:     fileConfig{},
			wantErr: assert.Error,
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
