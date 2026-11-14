package helpers

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

// encodeEvidence expresses the package locations as CycloneDX evidence occurrences, the standard field other tools
// read: one occurrence per distinct path on the scanned filesystem (for a file within an archive, the real path of the
// outermost archive). The layer and the path within an archive stay in the syft:location properties: an occurrence's
// additionalContext is written by cyclonedx-go as an XML attribute that the schema does not allow, and this model is
// what the public cyclonedxhelpers.ToFormatModel returns, so it must be valid in every format and spec version.
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
// otherwise be a second location for one file. Occurrence paths are rooted, as the names of file components are, so
// that a package location and the file it names agree.
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
		locations = append(locations, file.NewLocation(path))
	}
	return locations
}

func rootedPath(path string) string {
	return "/" + strings.TrimPrefix(path, "/")
}
