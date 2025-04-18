package internal

import (
	"context"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

func AllRegularFiles(ctx context.Context, resolver file.Resolver) (locations []file.Location) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for location := range resolver.AllLocations(ctx) {
		resolvedLocations, err := resolver.FilesByPath(location.RealPath)
		if err != nil {
			log.Debugf("unable to resolve %+v: %+v", location, err)
			continue
		}

		for _, resolvedLocation := range resolvedLocations {
			metadata, err := resolver.FileMetadataByLocation(resolvedLocation)
			if err != nil {
				log.Debugf("unable to get metadata for %+v: %+v", location, err)
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
