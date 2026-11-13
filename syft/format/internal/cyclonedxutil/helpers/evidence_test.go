package helpers

import (
	"fmt"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/testutils"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_encodeEvidence(t *testing.T) {
	tests := []struct {
		name      string
		locations []file.Location
		want      *cyclonedx.Evidence
	}{
		{
			name: "no locations",
		},
		{
			name: "one occurrence per location",
			locations: []file.Location{
				file.NewLocation("/opt/example"),
				file.NewLocation("/usr/bin/example"),
			},
			want: evidenceWithOccurrences("/opt/example", "/usr/bin/example"),
		},
		{
			name: "a path found in several layers is one occurrence",
			locations: []file.Location{
				file.NewLocationFromCoordinates(file.NewCoordinates("/usr/bin/example", "sha256:layer-1")),
				file.NewLocationFromCoordinates(file.NewCoordinates("/usr/bin/example", "sha256:layer-2")),
			},
			want: evidenceWithOccurrences("/usr/bin/example"),
		},
		{
			name: "a location without a path is not an occurrence",
			locations: []file.Location{
				file.NewLocation(""),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, encodeEvidence(tt.locations))
		})
	}
}

func Test_decodeEvidenceLocations(t *testing.T) {
	tests := []struct {
		name     string
		evidence *cyclonedx.Evidence
		known    []file.Location
		want     []file.Location
	}{
		{
			name: "no evidence",
		},
		{
			name:     "evidence without occurrences",
			evidence: &cyclonedx.Evidence{},
		},
		{
			name:     "a location per occurrence",
			evidence: evidenceWithOccurrences("/usr/bin/example", "/opt/example"),
			want: []file.Location{
				file.NewLocation("/usr/bin/example"),
				file.NewLocation("/opt/example"),
			},
		},
		{
			name:     "empty and repeated occurrences are skipped",
			evidence: evidenceWithOccurrences("/usr/bin/example", "", "/usr/bin/example"),
			want: []file.Location{
				file.NewLocation("/usr/bin/example"),
			},
		},
		{
			name:     "an occurrence for a known path is skipped",
			evidence: evidenceWithOccurrences("/usr/bin/example", "/opt/example"),
			known: []file.Location{
				file.NewLocationFromCoordinates(file.NewCoordinates("/usr/bin/example", "sha256:layer-1")),
			},
			want: []file.Location{
				file.NewLocation("/opt/example"),
			},
		},
		{
			// syft locations carry no line, so occurrences that differ only by line are one location
			name: "occurrences on different lines of one file are one location",
			evidence: &cyclonedx.Evidence{Occurrences: &[]cyclonedx.EvidenceOccurrence{
				{Location: "src/index.js", Line: new(1)},
				{Location: "src/index.js", Line: new(7)},
			}},
			want: []file.Location{
				file.NewLocation("src/index.js"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, decodeEvidenceLocations(tt.evidence, tt.known))
		})
	}
}

func Test_evidenceLocationsRoundTrip(t *testing.T) {
	want := []file.Coordinates{
		file.NewCoordinates("/opt/example", "sha256:layer-1"),
		file.NewCoordinates("/usr/bin/example", "sha256:layer-1"),
		file.NewCoordinates("/usr/bin/example", "sha256:layer-2"),
	}

	var locations []file.Location
	for _, c := range want {
		locations = append(locations, file.NewLocationFromCoordinates(c))
	}

	encoded := EncodeComponent(pkg.Package{Name: "example", Locations: file.NewLocationSet(locations...)}, "", file.LocationSorter(nil))
	require.Equal(t, evidenceWithOccurrences("/opt/example", "/usr/bin/example"), encoded.Evidence)

	// the encoder writes each location as both a syft:location property and an evidence occurrence; decoding must
	// yield each location once
	decoded := decodeComponent(&encoded)
	assert.ElementsMatch(t, want, decoded.Locations.CoordinateSet().ToSlice())
}

// the occurrences come from an SBOM that may not be trusted, so decoding them may not cost more than a fixed amount
// of memory per occurrence: ten times the occurrences may take about ten times the memory, and no more.
func Test_decodeEvidenceLocations_memoryIsProportionalToInput(t *testing.T) {
	measure := func(count int) uint64 {
		paths := make([]string, count)
		for i := range paths {
			paths[i] = fmt.Sprintf("/usr/lib/example/%d", i)
		}
		evidence := evidenceWithOccurrences(paths...)

		var got []file.Location
		allocated := testutils.MeasureAlloc(t, func() {
			got = decodeEvidenceLocations(evidence, nil)
		})
		require.Len(t, got, count)
		return allocated
	}

	small := measure(2_000)
	large := measure(20_000)

	assert.Less(t, large, small*20, "decoding 10x the occurrences allocated %d bytes, up from %d", large, small)
	assert.Less(t, large, uint64(20_000*1024), "decoding allocated more than 1KiB per occurrence")
}

func evidenceWithOccurrences(locations ...string) *cyclonedx.Evidence {
	occurrences := make([]cyclonedx.EvidenceOccurrence, len(locations))
	for i, location := range locations {
		occurrences[i] = cyclonedx.EvidenceOccurrence{Location: location}
	}
	return &cyclonedx.Evidence{Occurrences: &occurrences}
}
