package source

import (
	"github.com/anchore/syft/internal/log"
)

func AllRegularFiles(resolver FileResolver) (locations []Location) {
	for location := range resolver.AllLocations() {
		resolvedLocations, err := resolver.FilesByPath(location.RealPath)
		if err != nil {
			log.Warnf("unable to resolve %+v: %+v", location, err)
			continue
		}

		for _, resolvedLocation := range resolvedLocations {
			metadata, err := resolver.FileMetadataByLocation(resolvedLocation)
			if err != nil {
				log.Warnf("unable to get metadata for %+v: %+v", location, err)
				continue
			}

			if metadata.Type != RegularFile {
				continue
			}
			locations = append(locations, resolvedLocation)
		}
	}
	return locations
}
