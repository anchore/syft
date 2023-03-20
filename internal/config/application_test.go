package config

import (
	"os"
	"path"
	"testing"

	"github.com/adrg/xdg"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO: set negative case when config.yaml is no longer a valid option
func TestApplicationConfig(t *testing.T) {
	// disable homedir package cache for testing
	originalCacheOpt := homedir.DisableCache
	homedir.DisableCache = true
	t.Cleanup(func() {
		homedir.DisableCache = originalCacheOpt
	})

	// config is picked up at desired configuration paths
	// VALID: .syft.yaml, .syft/config.yaml, ~/.syft.yaml, <XDG_CONFIG_HOME>/syft/config.yaml
	// DEPRECATED: config.yaml is currently supported by
	tests := []struct {
		name       string
		setup      func(t *testing.T) string
		assertions func(t *testing.T, app *Application)
		cleanup    func()
	}{
		{
			name: "explicit config",
			setup: func(t *testing.T) string {
				return "./test-fixtures/.syft.yaml"
			}, // no-op for explicit config
			assertions: func(t *testing.T, app *Application) {
				assert.Equal(t, "test-explicit-config", app.File)
			},
		},
		{
			name: "current working directory named config",
			setup: func(t *testing.T) string {
				err := os.Chdir("./test-fixtures/config-wd-file") // change application cwd to test-fixtures
				require.NoError(t, err)
				return ""
			},
			assertions: func(t *testing.T, app *Application) {
				assert.Equal(t, "test-wd-named-config", app.File)
			},
		},
		{
			name: "current working directory syft dir config",
			setup: func(t *testing.T) string {
				err := os.Chdir("./test-fixtures/config-dir-test") // change application cwd to test-fixtures
				require.NoError(t, err)
				return ""
			},
			assertions: func(t *testing.T, app *Application) {
				assert.Equal(t, "test-dir-config", app.File)
			},
		},
		{
			name: "home directory file config",
			setup: func(t *testing.T) string {
				// Because Setenv affects the whole process, it cannot be used in parallel tests or
				// tests with parallel ancestors: see separate XDG test for consequence of this
				t.Setenv("HOME", "./test-fixtures/config-home-test/config-file")
				return ""
			},
			assertions: func(t *testing.T, app *Application) {
				assert.Equal(t, "test-home-config", app.File)
			},
		},
		{
			name: "XDG file config",
			setup: func(t *testing.T) string {
				wd, err := os.Getwd()
				require.NoError(t, err)
				configDir := path.Join(wd, "./test-fixtures/config-home-test") // set HOME to testdata
				t.Setenv("XDG_CONFIG_DIRS", configDir)
				xdg.Reload()
				return ""
			},
			assertions: func(t *testing.T, app *Application) {
				assert.Equal(t, "test-home-XDG-config", app.File)
			},
			cleanup: func() {
				require.NoError(t, os.Unsetenv("XDG_CONFIG_DIRS"))
				xdg.Reload()
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.cleanup != nil {
				t.Cleanup(test.cleanup)
			}
			wd, err := os.Getwd()
			require.NoError(t, err)

			defer os.Chdir(wd) // reset working directory after test
			application := &Application{}
			viperInstance := viper.New()

			// this will override home in case you are running this test locally and DO have a syft config
			// in your home directory... now it will be ignored. Same for XDG_CONFIG_DIRS.
			t.Setenv("HOME", "/foo/bar")
			t.Setenv("XDG_CONFIG_DIRS", "/foo/bar")

			configPath := test.setup(t)
			err = application.LoadAllValues(viperInstance, configPath)
			require.NoError(t, err)
			test.assertions(t, application)
		})
	}
}
