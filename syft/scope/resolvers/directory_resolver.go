package resolvers

import (
	"fmt"
	"io/ioutil"
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

func fileContents(path file.Path) ([]byte, error) {
	contents, err := ioutil.ReadFile(string(path))

	if err != nil {
		return nil, err
	}
	return contents, nil
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
func (s DirectoryResolver) MultipleFileContentsByRef(f ...file.Reference) (map[file.Reference]string, error) {
	refContents := make(map[file.Reference]string)
	for _, fileRef := range f {
		contents, err := fileContents(fileRef.Path)

		if err != nil {
			return nil, fmt.Errorf("could not read contents of file: %s", fileRef.Path)
		}
		refContents[fileRef] = string(contents)
	}
	return refContents, nil
}

// FileContentsByRef fetches file contents for a single file reference relative to a directory.
// If the path does not exist an error is returned.
func (s DirectoryResolver) FileContentsByRef(ref file.Reference) (string, error) {
	contents, err := fileContents(ref.Path)
	if err != nil {
		return "", fmt.Errorf("could not read contents of file: %s", ref.Path)
	}

	return string(contents), nil
}
