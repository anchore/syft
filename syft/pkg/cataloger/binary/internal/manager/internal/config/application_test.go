package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadAndValidate(t *testing.T) {
	tests := []struct {
		name      string
		expectErr bool
	}{
		{
			name: "valid-1.yaml",
		},
		{
			name: "valid-2.yaml",
		},
		{
			name:      "bad-implicit-name-collision.yaml",
			expectErr: true,
		},
		{
			name:      "bad-missing-version.yaml",
			expectErr: true,
		},
		{
			name:      "bad-missing-image.yaml",
			expectErr: true,
		},
		{
			name:      "bad-no-name.yaml",
			expectErr: true,
		},
		{
			name:      "bad-missing-image-platform.yaml",
			expectErr: true,
		},
		{
			name:      "bad-missing-image-ref.yaml",
			expectErr: true,
		},
		{
			name:      "bad-image-collision.yaml",
			expectErr: true,
		},
		{
			name:      "bad-missing-paths.yaml",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appConfig, err := read(filepath.Join("testdata", "app-configs", tt.name))
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, appConfig)
				assert.NoError(t, appConfig.Validate())
			}
		})
	}
}
