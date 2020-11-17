package source

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/anchore/syft/internal/log"
	"github.com/bmatcuk/doublestar"
)

var _ Resolver = &DirectoryResolver{}

// DirectoryResolver implements path and content access for the directory data source.
type DirectoryResolver struct {
	Path string
}

// Stringer to represent a directory path data source
func (s DirectoryResolver) String() string {
	return fmt.Sprintf("dir:%s", s.Path)
}

// FilesByPath returns all file.References that match the given paths from the directory.
func (s DirectoryResolver) FilesByPath(userPaths ...string) ([]Location, error) {
	var references = make([]Location, 0)

	for _, userPath := range userPaths {
		userStrPath := userPath

		if filepath.IsAbs(userStrPath) {
			// a path relative to root should be prefixed with the resolvers directory path, otherwise it should be left as is
			userStrPath = path.Join(s.Path, userStrPath)
		}
		fileMeta, err := os.Stat(userStrPath)
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			log.Errorf("path (%s) is not valid: %v", userStrPath, err)
		}

		// don't consider directories
		if fileMeta.IsDir() {
			continue
		}

		references = append(references, NewLocation(userStrPath))
	}

	return references, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern from any layer in the image.
func (s DirectoryResolver) FilesByGlob(patterns ...string) ([]Location, error) {
	result := make([]Location, 0)

	for _, pattern := range patterns {
		pathPattern := path.Join(s.Path, pattern)
		pathMatches, err := doublestar.Glob(pathPattern)
		if err != nil {
			return nil, err
		}
		for _, matchedPath := range pathMatches {
			fileMeta, err := os.Stat(matchedPath)
			if err != nil {
				continue
			}

			// don't consider directories
			if fileMeta.IsDir() {
				continue
			}

			result = append(result, NewLocation(matchedPath))
		}
	}

	return result, nil
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another file. For the
// DirectoryResolver, this is a simple path lookup.
func (s *DirectoryResolver) RelativeFileByPath(_ Location, path string) *Location {
	paths, err := s.FilesByPath(path)
	if err != nil {
		return nil
	}
	if len(paths) == 0 {
		return nil
	}

	return &paths[0]
}

// MultipleFileContentsByLocation returns the file contents for all file.References relative a directory.
func (s DirectoryResolver) MultipleFileContentsByLocation(locations []Location) (map[Location]string, error) {
	refContents := make(map[Location]string)
	for _, location := range locations {
		contents, err := fileContents(location.Path)

		if err != nil {
			return nil, fmt.Errorf("could not read contents of file: %s", location.Path)
		}
		refContents[location] = string(contents)
	}
	return refContents, nil
}

// FileContentsByLocation fetches file contents for a single file reference relative to a directory.
// If the path does not exist an error is returned.
func (s DirectoryResolver) FileContentsByLocation(location Location) (string, error) {
	contents, err := fileContents(location.Path)
	if err != nil {
		return "", fmt.Errorf("could not read contents of file: %s", location.Path)
	}

	return string(contents), nil
}

func fileContents(path string) ([]byte, error) {
	contents, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}
	return contents, nil
}
