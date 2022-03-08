package config

import (
	"github.com/docker/docker/pkg/homedir"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func TestApplication_parseFile(t *testing.T) {
	tests := []struct {
		name     string
		config   Application
		expected string
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name: "expand home dir",
			config: Application{
				File: "~/place.txt",
			},
			expected: filepath.Join(homedir.Get(), "place.txt"),
		},
		{
			name: "passthrough other paths",
			config: Application{
				File: "/other/place.txt",
			},
			expected: "/other/place.txt",
		},
		{
			name: "no path",
			config: Application{
				File: "",
			},
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.config

			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			tt.wantErr(t, cfg.parseFile())
			assert.Equal(t, tt.expected, cfg.File)
		})
	}
}
