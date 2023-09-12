package cyclonedxjson

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
)

func TestFormatVersions(t *testing.T) {
	tests := []struct {
		name            string
		version         string
		expectedVersion string
	}{
		{

			"cyclonedx-json should default to v1.4",
			"",
			cyclonedx.SpecVersion1_4.String(),
		},
		{

			"cyclonedx-json should encode for v1.5",
			"v1.5",
			cyclonedx.SpecVersion1_5.String(),
		},
		{

			"cyclonedx-json should encode for v1.3",
			"v1.3",
			cyclonedx.SpecVersion1_3.String(),
		},
		{

			"cyclonedx-json should encode for v1.2",
			"v1.2",
			cyclonedx.SpecVersion1_2.String(),
		},
		{

			"cyclonedx-json should encode for v1.1",
			"v1.1",
			cyclonedx.SpecVersion1_1.String(),
		},
		{

			"cyclonedx-json should encode for v1.0",
			"v1.0",
			cyclonedx.SpecVersion1_0.String(),
		},
	}

	for _, c := range tests {
		c := c
		t.Run(c.name, func(t *testing.T) {
			sbomFormat := Format(c.version)
			if sbomFormat.ID() != ID {
				t.Errorf("expected ID %q, got %q", ID, sbomFormat.ID())
			}

			if sbomFormat.Version() != c.expectedVersion {
				t.Errorf("expected version %q, got %q", c.version, sbomFormat.Version())
			}
		})
	}
}
