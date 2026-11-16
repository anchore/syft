package helpers

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

// encodeEvidence expresses the package locations as CycloneDX evidence occurrences, the standard field other tools
// read: one occurrence per distinct path on the scanned filesystem (for a file within an archive, the real path of the
// outermost archive). The layer and the path within an archive are stated only in the syft:location properties.
// Annotations are not written.
func encodeEvidence(locations []file.Location) *cyclonedx.Evidence {
	var occurrences []cyclonedx.EvidenceOccurrence
	seen := strset.New()
	for _, l := range locations {
		if l.RealPath == "" || seen.Has(l.RealPath) {
			continue
		}
		seen.Add(l.RealPath)
		occurrences = append(occurrences, cyclonedx.EvidenceOccurrence{Location: l.RealPath})
	}
	if len(occurrences) == 0 {
		return nil
	}
	return &cyclonedx.Evidence{Occurrences: &occurrences}
}

// decodeEvidenceLocations returns a location for each distinct evidence occurrence path that none of the known
// locations already covers. The known locations are the ones decoded from syft:location properties: they describe a
// path more fully than an occurrence can (layer, path within an archive), so an occurrence for the same path would
// otherwise be a second location for one file.
//
// An occurrence becomes a location by the rules the rest of this decoder already applies, and no others:
//   - every non-empty occurrence location is accepted
//   - the path is rooted the way the name of a file component is (see rootedPath) and is otherwise kept as written
//   - the location holds only coordinates, as a location decoded from syft:location properties does
func decodeEvidenceLocations(evidence *cyclonedx.Evidence, known []file.Location) []file.Location {
	if evidence == nil || evidence.Occurrences == nil {
		return nil
	}

	paths := strset.New()
	for _, l := range known {
		paths.Add(rootedPath(l.RealPath))
	}

	var locations []file.Location
	for _, occurrence := range *evidence.Occurrences {
		if occurrence.Location == "" {
			continue
		}
		path := rootedPath(occurrence.Location)
		if paths.Has(path) {
			continue
		}
		paths.Add(path)
		locations = append(locations, file.Location{
			LocationData: file.LocationData{Coordinates: file.NewCoordinates(path, "")},
		})
	}
	return locations
}

// rootedPath is the path relative to the scan root: file component names and evidence occurrence locations in
// documents from other tools are commonly relative, and syft paths are absolute.
func rootedPath(path string) string {
	return "/" + strings.TrimPrefix(path, "/")
}
