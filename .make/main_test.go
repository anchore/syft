package main

import (
	"os"
	"testing"

	"github.com/anchore/go-make/config"
	"github.com/anchore/go-make/tasks/gotest"
)

func TestRaceEnabled(t *testing.T) {
	tests := []struct {
		name string
		env  string // "" means RACE is unset
		ci   bool
		want bool
	}{
		{name: "default in CI", ci: true, want: true},
		{name: "default locally", ci: false, want: false},
		{name: "explicitly off in CI", env: "false", ci: true, want: false},
		{name: "explicitly on locally", env: "true", ci: false, want: true},
		{name: "unparseable falls back to default", env: "yes-please", ci: true, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// always go through t.Setenv (it registers the restore) so an ambient
			// RACE from the caller's environment can't leak into the unset cases
			t.Setenv("RACE", tt.env)
			if tt.env == "" {
				os.Unsetenv("RACE")
			}
			orig := config.CI
			config.CI = tt.ci
			t.Cleanup(func() { config.CI = orig })

			if got := raceEnabled(); got != tt.want {
				t.Errorf("raceEnabled() = %v, want %v", got, tt.want)
			}

			// the gotest suites get the same answer through the functional option
			var cfg gotest.Config
			race()(&cfg)
			if cfg.Race != tt.want {
				t.Errorf("race() set Race = %v, want %v", cfg.Race, tt.want)
			}
		})
	}
}
