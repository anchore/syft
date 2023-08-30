package internal

import (
	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

func AllRegularFiles(resolver file.Resolver) (locations []file.Location) {
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

			if metadata.Type != stereoscopeFile.TypeRegular {
				continue
			}
			locations = append(locations, resolvedLocation)
		}
	}
	return locations
}
