package python

import (
	"path/filepath"

	"github.com/anchore/syft/syft/source"
)

type packageEntry struct {
	Metadata   source.FileData
	FileRecord *source.FileData
	TopPackage *source.FileData
}

// newPackageEntry returns a new packageEntry to be processed relative to what information is available in the given FileResolver.
func newPackageEntry(resolver source.FileResolver, metadataLocation source.Location) *packageEntry {
	// we've been given a file reference to a specific wheel METADATA file. note: this may be for a directory
	// or for an image... for an image the METADATA file may be present within multiple layers, so it is important
	// to reconcile the RECORD path to the same layer (or a lower layer). The same is true with the top_level.txt file.

	// lets find the RECORD file relative to the directory where the METADATA file resides (in path AND layer structure)
	recordPath := filepath.Join(filepath.Dir(metadataLocation.Path), "RECORD")
	recordLocation := resolver.RelativeFileByPath(metadataLocation, recordPath)

	// a top_level.txt file specifies the python top-level packages (provided by this python package) installed into site-packages
	parentDir := filepath.Dir(metadataLocation.Path)
	topLevelPath := filepath.Join(parentDir, "top_level.txt")
	topLevelLocation := resolver.RelativeFileByPath(metadataLocation, topLevelPath)

	// build an entry that will later be populated with contents when the request is executed
	entry := &packageEntry{
		Metadata: source.FileData{
			Location: metadataLocation,
		},
	}

	if recordLocation != nil {
		entry.FileRecord = &source.FileData{
			Location: *recordLocation,
		}
	}

	if topLevelLocation != nil {
		entry.TopPackage = &source.FileData{
			Location: *topLevelLocation,
		}
	}
	return entry
}
