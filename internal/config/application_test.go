package config

import (
	"github.com/adrg/xdg"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"os"
	"path"
	"testing"
)

// TODO: set negative case when config.yaml is no longer a valid option
func TestApplicationConfig(t *testing.T) {
	// config is picked up at desired configuration paths
	// VALID: .syft.yaml, .syft/config.yaml, ~/.syft.yaml, <XDG_CONFIG_HOME>/syft/config.yaml
	// DEPRECATED: .config.yaml is currently supported by
	tests := []struct {
		name       string
		setup      func(t *testing.T) string
		assertions func(t *testing.T, app *Application)
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
				if err != nil {
					t.Fatalf("%s failed to change cwd: %+v", t.Name(), err)
				}
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
				// Because Setenv affects the whole process, it cannot be used in parallel tests or
				// tests with parallel ancestors: see separate XDG test for consequence of this
				t.Setenv("HOME", "./test-fixtures/config-home-test") // set HOME to testdata
				return ""
			},
			assertions: func(t *testing.T, app *Application) {
				assert.Equal(t, "test-home-config", app.File)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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

// NOTE: this has to be separate for now because of t.Setenv behavior
// if this was included in the above table test then HOMEDIR would always
// be set; we would never fall through to the XDG case
func TestApplication_LoadAllValues_XDG(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %+v", err)
	}
	defer os.Chdir(wd) // reset working directory after test
	application := &Application{}
	viperInstance := viper.New()

	// NOTE: we need to temporarily unset HOME or we never reach the XDG_CONFIG_HOME check
	t.Setenv("HOME", "/foo/bar")
	configDir := path.Join(wd, "./test-fixtures/config-xdg-dir-test") // set HOME to testdata
	t.Setenv("XDG_CONFIG_DIRS", configDir)
	xdg.Reload()

	err = application.LoadAllValues(viperInstance, "")
	if err != nil {
		t.Fatalf("failed to load application config: %+v", err)
	}

	assert.Equal(t, "test-home-XDG-config", application.File)
}
