package helpers

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

const (
	occurrenceLayerIDPrefix  = "layerID: "
	occurrenceFullPathPrefix = "fullPath: "
	occurrenceContextDivider = "; "
)

// encodeEvidence expresses the package locations as CycloneDX evidence occurrences, the standard field other tools
// read. The location of an occurrence is a path on the scanned filesystem: for a file within an archive it is the
// real path of the outermost archive. What else identifies a syft location (the layer it was found in and the full
// path through any archives) is written as the additional context of the occurrence, so there is an occurrence for
// each distinct set of coordinates. Annotations are not written.
func encodeEvidence(locations []file.Location) *cyclonedx.Evidence {
	var occurrences []cyclonedx.EvidenceOccurrence
	seen := map[file.Coordinates]struct{}{}
	for _, l := range locations {
		if l.RealPath == "" {
			continue
		}
		if _, ok := seen[l.Coordinates]; ok {
			continue
		}
		seen[l.Coordinates] = struct{}{}
		occurrences = append(occurrences, cyclonedx.EvidenceOccurrence{
			Location:          l.RealPath,
			AdditionalContext: encodeOccurrenceContext(l.Coordinates),
		})
	}
	if len(occurrences) == 0 {
		return nil
	}
	return &cyclonedx.Evidence{Occurrences: &occurrences}
}

// encodeOccurrenceContext writes the layer and the full path of the coordinates as "layerID: <id>; fullPath: <path>",
// leaving out whichever is blank.
func encodeOccurrenceContext(c file.Coordinates) string {
	var parts []string
	if c.FileSystemID != "" {
		parts = append(parts, occurrenceLayerIDPrefix+c.FileSystemID)
	}
	if c.FullPath != "" {
		parts = append(parts, occurrenceFullPathPrefix+c.FullPath)
	}
	return strings.Join(parts, occurrenceContextDivider)
}

// decodeOccurrenceCoordinates returns the coordinates an occurrence describes. The location is rooted, as the names
// of file components are, so that a package location and the file it names agree. Additional context that syft did
// not write (other tools use it for things like code snippets) is ignored, as is a full path that is not within the
// location.
func decodeOccurrenceCoordinates(occurrence cyclonedx.EvidenceOccurrence) file.Coordinates {
	c := file.Coordinates{RealPath: rootedPath(occurrence.Location)}

	context := occurrence.AdditionalContext
	if rest, ok := strings.CutPrefix(context, occurrenceLayerIDPrefix); ok {
		c.FileSystemID, context, _ = strings.Cut(rest, occurrenceContextDivider)
	}
	if fullPath, ok := strings.CutPrefix(context, occurrenceFullPathPrefix); ok && strings.HasPrefix(fullPath, c.RealPath+file.ArchivePathSeparator) {
		c.FullPath = fullPath
	}
	return c
}

// decodeEvidenceLocations returns a location for each distinct evidence occurrence that none of the known locations
// already covers. The known locations are the ones decoded from syft:location properties: a document that has them
// states each location there, so an occurrence for the same path would otherwise be a second location for one file.
func decodeEvidenceLocations(evidence *cyclonedx.Evidence, known []file.Location) []file.Location {
	if evidence == nil || evidence.Occurrences == nil {
		return nil
	}

	knownPaths := strset.New()
	for _, l := range known {
		knownPaths.Add(rootedPath(l.RealPath))
	}

	var locations []file.Location
	seen := map[file.Coordinates]struct{}{}
	for _, occurrence := range *evidence.Occurrences {
		if occurrence.Location == "" {
			continue
		}
		c := decodeOccurrenceCoordinates(occurrence)
		if knownPaths.Has(c.RealPath) {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		locations = append(locations, file.NewLocationFromCoordinates(c))
	}
	return locations
}

func rootedPath(path string) string {
	return "/" + strings.TrimPrefix(path, "/")
}
