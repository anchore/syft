package helpers

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

// encodeEvidence expresses the package locations as CycloneDX evidence occurrences, the standard field other tools
// read. An occurrence carries only a path, so the same locations are also written as syft:location properties, which
// keep the layer and annotations; each distinct path is written once no matter how many layers it was found in.
func encodeEvidence(locations []file.Location) *cyclonedx.Evidence {
	var occurrences []cyclonedx.EvidenceOccurrence
	paths := strset.New()
	for _, l := range locations {
		if l.RealPath == "" || paths.Has(l.RealPath) {
			continue
		}
		paths.Add(l.RealPath)
		occurrences = append(occurrences, cyclonedx.EvidenceOccurrence{Location: l.RealPath})
	}
	if len(occurrences) == 0 {
		return nil
	}
	return &cyclonedx.Evidence{Occurrences: &occurrences}
}

// decodeEvidenceLocations returns a location for each distinct evidence occurrence path that none of the known
// locations already covers. The known locations are the ones decoded from syft:location properties: they describe a
// path more fully than an occurrence can (layer, annotations) and never compare equal to a location built from an
// occurrence, so an occurrence for the same path would otherwise be a second location for one file.
func decodeEvidenceLocations(evidence *cyclonedx.Evidence, known []file.Location) []file.Location {
	if evidence == nil || evidence.Occurrences == nil {
		return nil
	}

	paths := strset.New()
	for _, l := range known {
		paths.Add(l.RealPath)
	}

	var locations []file.Location
	for _, occurrence := range *evidence.Occurrences {
		if occurrence.Location == "" || paths.Has(occurrence.Location) {
			continue
		}
		paths.Add(occurrence.Location)
		locations = append(locations, file.NewLocation(occurrence.Location))
	}
	return locations
}
