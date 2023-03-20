package config

import (
	"os"
	"path"
	"testing"

	"github.com/adrg/xdg"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TODO: set negative case when config.yaml is no longer a valid option
func TestApplicationConfig(t *testing.T) {
	// config is picked up at desired configuration paths
	// VALID: .syft.yaml, .syft/config.yaml, ~/.syft.yaml, <XDG_CONFIG_HOME>/syft/config.yaml
	// DEPRECATED: config.yaml is currently supported by
	tests := []struct {
		name       string
		setup      func(t *testing.T) string
		assertions func(t *testing.T, app *Application)
		Cleanup    func(t *testing.T)
	}{
		{
			name: "explicit config",
			setup: func(t *testing.T) string {
				return "./test-fixtures/.syft.yaml"
			}, // no-op for explicit config
			assertions: func(t *testing.T, app *Application) {
				assert.Equal(t, "test-explicit-config", app.File)
			},
			Cleanup: func(t *testing.T) {},
		},
		{
			name: "current working directory named config",
			setup: func(t *testing.T) string {
				err := os.Chdir("./test-fixtures/config-wd-file") // change application cwd to test-fixtures
				if err != nil {
					t.Fatalf("%s failed to change cwd: %+v", t.Name(), err)
				}
				return ""
			},
			assertions: func(t *testing.T, app *Application) {
				assert.Equal(t, "test-wd-named-config", app.File)
			},
			Cleanup: func(t *testing.T) {},
		},
		{
			name: "current working directory syft dir config",
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
			Cleanup: func(t *testing.T) {},
		},
		{
			name: "home directory file config",
			setup: func(t *testing.T) string {
				// Because Setenv affects the whole process, it cannot be used in parallel tests or
				// tests with parallel ancestors: see separate XDG test for consequence of this
				t.Setenv("HOME", "./test-fixtures/config-home-test")
				err := os.Link("./test-fixtures/config-home-test/config-file/.syft.yaml", "./test-fixtures/config-home-test/.syft.yaml")
				if err != nil {
					t.Fatalf("%s failed to link home config: %+v", t.Name(), err)
				}
				return ""
			},
			assertions: func(t *testing.T, app *Application) {
				assert.Equal(t, "test-home-config", app.File)
			},
			Cleanup: func(t *testing.T) {
				err := os.Remove("./test-fixtures/config-home-test/.syft.yaml") //
				if err != nil {
					t.Fatalf("%s failed to remove home config link: %+v", t.Name(), err)
				}
			},
		},
		{
			name: "XDG file config",
			setup: func(t *testing.T) string {
				wd, err := os.Getwd()
				if err != nil {
					t.Fatalf("%s: failed to get working directory: %+v", t.Name(), err)
				}
				configDir := path.Join(wd, "./test-fixtures/config-home-test") // set HOME to testdata
				t.Setenv("XDG_CONFIG_DIRS", configDir)
				xdg.Reload()
				return ""
			},
			assertions: func(t *testing.T, app *Application) {
				assert.Equal(t, "test-home-XDG-config", app.File)
			},
			Cleanup: func(t *testing.T) {},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer test.Cleanup(t)
			wd, err := os.Getwd()
			if err != nil {
				t.Fatalf("failed to get working directory: %+v", err)
			}
			defer os.Chdir(wd) // reset working directory after test
			application := &Application{}
			viperInstance := viper.New()

			configPath := test.setup(t)
			err = application.LoadAllValues(viperInstance, configPath)
			if err != nil {
				t.Fatalf("failed to load application config: %+v", err)
			}
			test.assertions(t, application)
		})
	}
}
