package helpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			// the location of an occurrence is a path on the scanned filesystem, so files within one archive share the
			// archive as their location; the full paths stay in the syft:location properties
			name: "files within an archive are one occurrence of the outermost archive",
			locations: []file.Location{
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath: "/app.war",
					FullPath: "/app.war!/WEB-INF/lib/dep.jar",
				}),
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/app.war",
					FileSystemID: "sha256:layer-1",
					FullPath:     "/app.war!/WEB-INF/lib/other.jar!/META-INF/MANIFEST.MF",
				}),
			},
			want: evidenceWithOccurrences("/app.war"),
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
				occurrenceLocation("/usr/bin/example"),
				occurrenceLocation("/opt/example"),
			},
		},
		{
			name:     "empty and repeated occurrences are skipped",
			evidence: evidenceWithOccurrences("/usr/bin/example", "", "/usr/bin/example"),
			want: []file.Location{
				occurrenceLocation("/usr/bin/example"),
			},
		},
		{
			name:     "an occurrence for a known path is skipped",
			evidence: evidenceWithOccurrences("/usr/bin/example", "/opt/example"),
			known: []file.Location{
				file.NewLocationFromCoordinates(file.NewCoordinates("/usr/bin/example", "sha256:layer-1")),
			},
			want: []file.Location{
				occurrenceLocation("/opt/example"),
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
				occurrenceLocation("/src/index.js"),
			},
		},
		{
			// file components are decoded with rooted names, and a package location must name the same file
			name:     "a relative occurrence is rooted",
			evidence: evidenceWithOccurrences("src/index.js", "/src/index.js", "/opt/example"),
			want: []file.Location{
				occurrenceLocation("/src/index.js"),
				occurrenceLocation("/opt/example"),
			},
		},
		{
			// other tools use the additional context for things like code snippets; only the location is read
			name: "the additional context of an occurrence is ignored",
			evidence: &cyclonedx.Evidence{Occurrences: &[]cyclonedx.EvidenceOccurrence{
				{Location: "src/index.js", AdditionalContext: "const _ = require('lodash')"},
				{Location: "/usr/bin/example", AdditionalContext: "layerID: sha256:layer-1"},
			}},
			want: []file.Location{
				occurrenceLocation("/src/index.js"),
				occurrenceLocation("/usr/bin/example"),
			},
		},
		{
			// a path is rooted and nothing else, as the name of a file component and a syft:location path are
			name:     "an occurrence path is otherwise kept as written",
			evidence: evidenceWithOccurrences("./src/index.js", `packages\example.deb`, "a/../b"),
			want: []file.Location{
				occurrenceLocation("/./src/index.js"),
				occurrenceLocation(`/packages\example.deb`),
				occurrenceLocation("/a/../b"),
			},
		},
		{
			name:     "a relative occurrence for a known path is skipped",
			evidence: evidenceWithOccurrences("usr/bin/example"),
			known: []file.Location{
				file.NewLocationFromCoordinates(file.NewCoordinates("/usr/bin/example", "sha256:layer-1")),
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
		{RealPath: "/app.war", FileSystemID: "sha256:layer-2", FullPath: "/app.war!/WEB-INF/lib/dep.jar"},
	}

	var locations []file.Location
	for _, c := range want {
		locations = append(locations, file.NewLocationFromCoordinates(c))
	}

	encoded := EncodeComponent(pkg.Package{Name: "example", Locations: file.NewLocationSet(locations...)}, "", file.LocationSorter(nil))
	require.NotNil(t, encoded.Evidence)
	require.Len(t, *encoded.Evidence.Occurrences, 3, "one occurrence per distinct path")

	t.Run("properties and occurrences", func(t *testing.T) {
		// each location is both a syft:location property and an evidence occurrence; decoding must yield each
		// location once
		decoded := decodeComponent(&encoded)
		assert.ElementsMatch(t, want, decoded.Locations.CoordinateSet().ToSlice())
	})

	t.Run("occurrences alone", func(t *testing.T) {
		// without the properties, a reader that knows only the standard field still gets each path
		onlyOccurrences := cyclonedx.Component{Name: encoded.Name, Evidence: encoded.Evidence}
		decoded := decodeComponent(&onlyOccurrences)
		assert.ElementsMatch(t, []file.Coordinates{
			{RealPath: "/opt/example"},
			{RealPath: "/usr/bin/example"},
			{RealPath: "/app.war"},
		}, decoded.Locations.CoordinateSet().ToSlice())
	})
}

func evidenceWithOccurrences(locations ...string) *cyclonedx.Evidence {
	occurrences := make([]cyclonedx.EvidenceOccurrence, len(locations))
	for i, location := range locations {
		occurrences[i] = cyclonedx.EvidenceOccurrence{Location: location}
	}
	return &cyclonedx.Evidence{Occurrences: &occurrences}
}

// when a document states a path in syft:location properties, an evidence occurrence for the same path is not decoded
// as a second location: the properties win
func Test_decodeLocations_propertiesWinOverOccurrenceForSamePath(t *testing.T) {
	properties := map[string]string{
		"syft:location:0:path":    "/usr/bin/example",
		"syft:location:0:layerID": "sha256:layer-1",
	}
	evidence := &cyclonedx.Evidence{Occurrences: &[]cyclonedx.EvidenceOccurrence{
		{Location: "/usr/bin/example", AdditionalContext: "layerID: sha256:layer-2"},
	}}

	locations := decodeLocations(properties, evidence)
	got := locations.CoordinateSet().ToSlice()
	assert.Equal(t, []file.Coordinates{file.NewCoordinates("/usr/bin/example", "sha256:layer-1")}, got)
}

// a location decoded from an occurrence has the shape of one decoded from syft:location properties: coordinates only
func Test_decodeLocations_occurrenceLocationMatchesPropertyLocation(t *testing.T) {
	fromProperty := decodeLocations(map[string]string{"syft:location:0:path": "/usr/bin/example"}, nil).ToSlice()
	fromOccurrence := decodeLocations(nil, evidenceWithOccurrences("/usr/bin/example")).ToSlice()

	require.Len(t, fromProperty, 1)
	require.Len(t, fromOccurrence, 1)
	assert.Equal(t, fromProperty[0].LocationData, fromOccurrence[0].LocationData)
	assert.Empty(t, fromOccurrence[0].AccessPath)
}

func occurrenceLocation(path string) file.Location {
	return file.Location{LocationData: file.LocationData{Coordinates: file.NewCoordinates(path, "")}}
}
