package file

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/source"
)

func allRegularFiles(resolver source.FileResolver) (locations []source.Location) {
	for location := range resolver.AllLocations() {

		metadata, err := resolver.FileMetadataByLocation(location)
		if err != nil {
			log.Warnf("unable to get metadata for %+v: %+v", location, err)
			continue
		}

		// filter out anything that is not a regular file. Why not evaluate symlinks here? All symlinks resolve to
		// either a) another path with a file/dir or b) nothing. Any other existing path will already be returned
		// from resolver.AllLocations().

		// TODO: a challenge for the future: can we allow for symlink resolution here for consumers that need to observe file nodes with the virtual paths intact?
		// I tried this out but ran into a problem with the directory resolver; the requestPath() call misinterprets the real input path as if it's from
		// the root of the resolver directory.
		if metadata.Type != source.RegularFile {
			continue
		}

		locations = append(locations, location)

	}
	return locations
}
