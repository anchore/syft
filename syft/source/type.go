package source

import (
	"fmt"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/afero"
)

// Type represents the optional prefixed string at the beginning of a user request (e.g. "docker:").
type Type string

const (
	// UnknownType is the default scheme
	UnknownType Type = "UnknownType"
	// DirectoryType indicates the source being cataloged is a directory on the root filesystem
	DirectoryType Type = "directory"
	// ImageType indicates the source being cataloged is a container image
	ImageType Type = "image"
	// FileType indicates the source being cataloged is a single file
	FileType Type = "file"
)

var AllTypes = []Type{
	DirectoryType,
	ImageType,
	FileType,
}

func DetectTypeFromScheme(fs afero.Fs, imageDetector sourceDetector, userInput string) (Type, image.Source, string, error) {
	switch {
	case strings.HasPrefix(userInput, "dir:"):
		dirLocation, err := homedir.Expand(strings.TrimPrefix(userInput, "dir:"))
		if err != nil {
			return UnknownType, image.UnknownSource, "", fmt.Errorf("unable to expand directory path: %w", err)
		}
		return DirectoryType, image.UnknownSource, dirLocation, nil

	case strings.HasPrefix(userInput, "file:"):
		fileLocation, err := homedir.Expand(strings.TrimPrefix(userInput, "file:"))
		if err != nil {
			return UnknownType, image.UnknownSource, "", fmt.Errorf("unable to expand directory path: %w", err)
		}
		return FileType, image.UnknownSource, fileLocation, nil
	}

	// try the most specific sources first and move out towards more generic sources.

	// first: let's try the image detector, which has more scheme parsing internal to stereoscope
	source, imageSpec, err := imageDetector(userInput)
	if err == nil && source != image.UnknownSource {
		return ImageType, source, imageSpec, nil
	}

	// next: let's try more generic sources (dir, file, etc.)
	location, err := homedir.Expand(userInput)
	if err != nil {
		return UnknownType, image.UnknownSource, "", fmt.Errorf("unable to expand potential directory path: %w", err)
	}

	fileMeta, err := fs.Stat(location)
	if err != nil {
		return UnknownType, source, "", nil
	}

	if fileMeta.IsDir() {
		return DirectoryType, source, location, nil
	}

	return FileType, source, location, nil
}
