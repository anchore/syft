package config

import (
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestApplicationConfig(t *testing.T) {
	// config is picked up at desired configuration paths
	// VALID: .syft.yaml, .syft/config.yaml, ~/.syft.yaml, <XDG_CONFIG_HOME>/syft/config.yaml
	// DEPRECATED: .config.yaml is currently supported by
	tests := []struct {
		name       string
		path       string
		setup      func(t *testing.T) string
		assertions func(t *testing.T, app *Application)
	}{
		{
			name: "explicit config",
			setup: func(t *testing.T) string {
				return "./test-fixtures/.syft.yaml"
			}, // no-op for explicit config
			assertions: func(t *testing.T, app *Application) {
				assert.Equal(t, "test-config", app.File)
			},
		},
		{
			name: "current working directory file config",
			setup: func(t *testing.T) string {
				err := os.Chdir("./test-fixtures") // change application cwd to test-fixtures
				if err != nil {
					t.Fatalf("%s failed to change cwd: %+v", t.Name(), err)
				}
				return ""
			},
			assertions: func(t *testing.T, app *Application) {
				assert.Equal(t, "test-config", app.File)
			},
		},
		{
			name: "current working directory dir config",
			setup: func(t *testing.T) string {
				err := os.Chdir("./test-fixtures/config-dir-test") // change application cwd to test-fixtures
				if err != nil {
					t.Fatalf("%s failed to change cwd: %+v", t.Name(), err)
				}
				return ""
			},
			assertions: func(t *testing.T, app *Application) {
				assert.Equal(t, "test-dir-config", app.File)
			},
		},
		{
			name: "home directory file config",
			setup: func(t *testing.T) string {
				t.Setenv("HOME", "./test-fixtures/config-home-test") // set HOME to testdata
				return ""
			},
			assertions: func(t *testing.T, app *Application) {
				assert.Equal(t, "test-home-config", app.File)
			},
		},
		//{ // I don't think this is a valid test case, as the XDG_CONFIG_HOME cannot be hit using the current homedir implementation
		//	// check $XDG_CONFIG_HOME then fall back to checking $XDG_CONFIG_DIRS
		//	name: "xdg config <appname>/config.yaml",
		//	setup: func(t *testing.T) string {
		//		// NOTE: we need to temporarily unset HOME or we never reach the XDG_CONFIG_HOME check
		//		t.Setenv("HOME", "")                                            // set HOME to testdata
		//		t.Setenv("XDG_CONFIG_HOME", "./test-fixtures/config-home-test") // set HOME to testdata
		//		return ""
		//	},
		//	assertions: func(t *testing.T, app *Application) {
		//		assert.Equal(t, "test-home-XDG-config", app.File)
		//	},
		//},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			application := &Application{}
			viperInstance := viper.New()

			configPath := test.setup(t)
			err := application.LoadAllValues(viperInstance, configPath)
			if err != nil {
				t.Fatalf("failed to load application config: %+v", err)
			}
			test.assertions(t, application)
		})
	}
}
