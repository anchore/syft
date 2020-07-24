package file

import (
	"archive/zip"
	"fmt"
	"os"
	"sort"

	"github.com/anchore/syft/internal"

	"github.com/anchore/syft/internal/log"
)

type ZipFileManifest map[string]os.FileInfo

func newZipManifest() ZipFileManifest {
	return make(ZipFileManifest)
}

func (z ZipFileManifest) Add(entry string, info os.FileInfo) {
	z[entry] = info
}

func (z ZipFileManifest) GlobMatch(patterns ...string) []string {
	uniqueMatches := internal.NewStringSet()

	for _, pattern := range patterns {
		for entry := range z {
			if GlobMatch(pattern, entry) {
				uniqueMatches.Add(entry)
			}
		}
	}

	results := uniqueMatches.ToSlice()
	sort.Strings(results)

	return results
}

func NewZipFileManifest(archivePath string) (ZipFileManifest, error) {
	zipReader, err := zip.OpenReader(archivePath)
	manifest := newZipManifest()
	if err != nil {
		return manifest, fmt.Errorf("unable to open zip archive (%s): %w", archivePath, err)
	}
	defer func() {
		err = zipReader.Close()
		if err != nil {
			log.Errorf("unable to close zip archive (%s): %w", archivePath, err)
		}
	}()

	for _, file := range zipReader.Reader.File {
		manifest.Add(file.Name, file.FileInfo())
	}
	return manifest, nil
}
