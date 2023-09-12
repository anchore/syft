package syftjson

import (
	"testing"

	"github.com/anchore/syft/internal"
)

func TestFormat(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{
			name:    "default version should use latest internal version",
			version: "",
		},
	}

	for _, c := range tests {
		c := c
		t.Run(c.name, func(t *testing.T) {
			sbomFormat := Format()
			if sbomFormat.ID() != ID {
				t.Errorf("expected ID %q, got %q", ID, sbomFormat.ID())
			}

			if sbomFormat.Version() != internal.JSONSchemaVersion {
				t.Errorf("expected version %q, got %q", c.version, sbomFormat.Version())
			}
		})
	}
}
