package file

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
)

// ZipFileManifest is a collection of paths and their file metadata.
type ZipFileManifest map[string]os.FileInfo

// NewZipFileManifest creates and returns a new ZipFileManifest populated with path and metadata from the given zip archive path.
func NewZipFileManifest(archivePath string) (ZipFileManifest, error) {
	zipReader, err := OpenZip(archivePath)
	manifest := make(ZipFileManifest)
	if err != nil {
		return manifest, fmt.Errorf("unable to open zip archive (%s): %w", archivePath, err)
	}
	defer func() {
		err = zipReader.Close()
		if err != nil {
			log.Warnf("unable to close zip archive (%s): %+v", archivePath, err)
		}
	}()

	for _, file := range zipReader.Reader.File {
		manifest.Add(file.Name, file.FileInfo())
	}
	return manifest, nil
}

// Add a new path and it's file metadata to the collection.
func (z ZipFileManifest) Add(entry string, info os.FileInfo) {
	z[entry] = info
}

// GlobMatch returns the path keys that match the given value(s).
func (z ZipFileManifest) GlobMatch(patterns ...string) []string {
	uniqueMatches := internal.NewStringSet()

	for _, pattern := range patterns {
		for entry := range z {
			// We want to match globs as if entries begin with a leading slash (akin to an absolute path)
			// so that glob logic is consistent inside and outside of ZIP archives
			normalizedEntry := normalizeZipEntryName(entry)

			if GlobMatch(pattern, normalizedEntry) {
				uniqueMatches.Add(entry)
			}
		}
	}

	results := uniqueMatches.ToSlice()
	sort.Strings(results)

	return results
}

// normalizeZipEntryName takes the given path entry and ensures it is prefixed with "/".
func normalizeZipEntryName(entry string) string {
	if !strings.HasPrefix(entry, "/") {
		return "/" + entry
	}

	return entry
}
