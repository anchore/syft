package file

import (
	"os"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/log"
)

// ZipFileManifest is a collection of paths and their file metadata.
type ZipFileManifest map[string]os.FileInfo

// NewZipFileManifest creates and returns a new ZipFileManifest populated with path and metadata from the given zip archive path.
func NewZipFileManifest(archivePath string) (ZipFileManifest, error) {
	zipReader, err := OpenZip(archivePath)
	manifest := make(ZipFileManifest)
	if err != nil {
		log.Debugf("unable to open zip archive (%s): %v", archivePath, err)
		return manifest, err
	}
	defer func() {
		err = zipReader.Close()
		if err != nil {
			log.Debugf("unable to close zip archive (%s): %+v", archivePath, err)
		}
	}()

	for _, file := range zipReader.File {
		manifest.Add(file.Name, file.FileInfo())
	}
	return manifest, nil
}

// Add a new path and it's file metadata to the collection.
func (z ZipFileManifest) Add(entry string, info os.FileInfo) {
	z[entry] = info
}

// GlobMatch returns the path keys that match the given value(s).
func (z ZipFileManifest) GlobMatch(caseInsensitive bool, patterns ...string) []string {
	uniqueMatches := strset.New()

	for _, pattern := range patterns {
		for entry := range z {
			// We want to match globs as if entries begin with a leading slash (akin to an absolute path)
			// so that glob logic is consistent inside and outside of ZIP archives
			normalizedEntry := normalizeZipEntryName(caseInsensitive, entry)

			if caseInsensitive {
				pattern = strings.ToLower(pattern)
			}
			if GlobMatch(pattern, normalizedEntry) {
				uniqueMatches.Add(entry)
			}
		}
	}

	results := uniqueMatches.List()
	sort.Strings(results)

	return results
}

// normalizeZipEntryName takes the given path entry and ensures it is prefixed with "/".
func normalizeZipEntryName(caseInsensitive bool, entry string) string {
	if caseInsensitive {
		entry = strings.ToLower(entry)
	}
	if !strings.HasPrefix(entry, "/") {
		return "/" + entry
	}

	return entry
}
