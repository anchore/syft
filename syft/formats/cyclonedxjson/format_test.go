package cyclonedxjson

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
)

func TestFormatVersions(t *testing.T) {
	tests := []struct {
		name            string
		expectedVersion string
	}{
		{

			"cyclonedx-json should default to v1.4",
			cyclonedx.SpecVersion1_4.String(),
		},
	}

	for _, c := range tests {
		c := c
		t.Run(c.name, func(t *testing.T) {
			sbomFormat := Format()
			if sbomFormat.ID() != ID {
				t.Errorf("expected ID %q, got %q", ID, sbomFormat.ID())
			}

			if sbomFormat.Version() != c.expectedVersion {
				t.Errorf("expected version %q, got %q", c.expectedVersion, sbomFormat.Version())
			}
		})
	}
}
