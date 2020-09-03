package resolvers

import (
	"fmt"
	"io"
	"os"
	"path"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/log"
	"github.com/bmatcuk/doublestar"
)

// DirectoryResolver implements path and content access for the directory data source.
type DirectoryResolver struct {
	Path string
}

// Stringer to represent a directory path data source
func (s DirectoryResolver) String() string {
	return fmt.Sprintf("dir://%s", s.Path)
}

// FilesByPath returns all file.References that match the given paths from the directory.
func (s DirectoryResolver) FilesByPath(userPaths ...file.Path) ([]file.Reference, error) {
	var references = make([]file.Reference, 0)

	for _, userPath := range userPaths {
		resolvedPath := path.Join(s.Path, string(userPath))
		_, err := os.Stat(resolvedPath)
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			log.Errorf("path (%s) is not valid: %v", resolvedPath, err)
		}
		filePath := file.Path(resolvedPath)
		references = append(references, file.NewFileReference(filePath))
	}

	return references, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern from any layer in the image.
func (s DirectoryResolver) FilesByGlob(patterns ...string) ([]file.Reference, error) {
	result := make([]file.Reference, 0)

	for _, pattern := range patterns {
		pathPattern := path.Join(s.Path, pattern)
		matches, err := doublestar.Glob(pathPattern)
		if err != nil {
			return result, err
		}
		for _, match := range matches {
			fileMeta, err := os.Stat(match)
			if err != nil {
				continue
			}
			if fileMeta.IsDir() {
				continue
			}
			matchedPath := file.Path(match)
			result = append(result, file.NewFileReference(matchedPath))
		}
	}

	return result, nil
}

// MultipleFileContentsByRef returns the file contents for all file.References relative a directory.
func (s DirectoryResolver) MultipleFileContentsByRef(f ...file.Reference) (map[file.Reference]io.Reader, error) {
	refContents := make(map[file.Reference]io.Reader)
	for _, fileRef := range f {
		targetFile, err := os.Open(string(fileRef.Path))
		if err != nil {
			return refContents, fmt.Errorf("could not open file=%q: %w", fileRef.Path, err)
		}

		refContents[fileRef] = targetFile
	}
	return refContents, nil
}
