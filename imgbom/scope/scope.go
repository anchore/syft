package scope

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

type DirectoryScope struct {
	Option Option
	Path   string
}

func (s DirectoryScope) String() string {
	return fmt.Sprintf("dir://%s", s.Path)
}

func (s DirectoryScope) FilesByPath(userPaths ...file.Path) ([]file.Reference, error) {
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

func (s DirectoryScope) FilesByGlob(patterns ...string) ([]file.Reference, error) {
	result := make([]file.Reference, 0)

	for _, pattern := range patterns {
		pathPattern := path.Join(s.Path, pattern)
		matches, err := filepath.Glob(pathPattern)
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

func (s DirectoryScope) MultipleFileContentsByRef(f ...file.Reference) (map[file.Reference]string, error) {
	refContents := make(map[file.Reference]string)
	for _, fileRef := range f {
		contents, err := fileContents(fileRef.Path)
		if err != nil {
			return refContents, fmt.Errorf("could not read contents of file: %s", fileRef.Path)
		}
		refContents[fileRef] = string(contents)
	}
	return refContents, nil
}

type ImageScope struct {
	Option   Option
	resolver FileResolver
	Image    *image.Image
}

func NewDirScope(path string, option Option) (DirectoryScope, error) {
	return DirectoryScope{
		Option: option,
		Path:   path,
	}, nil
}

func NewImageScope(img *image.Image, option Option) (ImageScope, error) {
	if img == nil {
		return ImageScope{}, fmt.Errorf("no image given")
	}

	resolver, err := getFileResolver(img, option)
	if err != nil {
		return ImageScope{}, fmt.Errorf("could not determine file resolver: %w", err)
	}

	return ImageScope{
		Option:   option,
		resolver: resolver,
		Image:    img,
	}, nil
}

func (s ImageScope) FilesByPath(paths ...file.Path) ([]file.Reference, error) {
	return s.resolver.FilesByPath(paths...)
}

func (s ImageScope) FilesByGlob(patterns ...string) ([]file.Reference, error) {
	return s.resolver.FilesByGlob(patterns...)
}

func (s ImageScope) MultipleFileContentsByRef(f ...file.Reference) (map[file.Reference]string, error) {
	return s.Image.MultipleFileContentsByRef(f...)
}
