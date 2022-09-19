package source

import (
	"fmt"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/afero"

	"github.com/anchore/stereoscope/pkg/image"
)

// Scheme represents the optional prefixed string at the beginning of a user request (e.g. "docker:").
type Scheme string

const (
	// UnknownScheme is the default scheme
	UnknownScheme Scheme = "UnknownScheme"
	// DirectoryScheme indicates the source being cataloged is a directory on the root filesystem
	DirectoryScheme Scheme = "DirectoryScheme"
	// ImageScheme indicates the source being cataloged is a container image
	ImageScheme Scheme = "ImageScheme"
	// FileScheme indicates the source being cataloged is a single file
	FileScheme Scheme = "FileScheme"
)

var AllSchemes = []Scheme{
	DirectoryScheme,
	ImageScheme,
	FileScheme,
}

func DetectScheme(fs afero.Fs, imageDetector sourceDetector, userInput string) (Scheme, image.Source, string, error) {
	switch {
	case strings.HasPrefix(userInput, "dir:"):
		dirLocation, err := homedir.Expand(strings.TrimPrefix(userInput, "dir:"))
		if err != nil {
			return UnknownScheme, image.UnknownSource, "", fmt.Errorf("unable to expand directory path: %w", err)
		}
		return DirectoryScheme, image.UnknownSource, dirLocation, nil

	case strings.HasPrefix(userInput, "file:"):
		fileLocation, err := homedir.Expand(strings.TrimPrefix(userInput, "file:"))
		if err != nil {
			return UnknownScheme, image.UnknownSource, "", fmt.Errorf("unable to expand directory path: %w", err)
		}
		return FileScheme, image.UnknownSource, fileLocation, nil
	}

	// try the most specific sources first and move out towards more generic sources.

	// first: let's try the image detector, which has more scheme parsing internal to stereoscope
	source, imageSpec, err := imageDetector(userInput)
	if err == nil && source != image.UnknownSource {
		return ImageScheme, source, imageSpec, nil
	}

	// next: let's try more generic sources (dir, file, etc.)
	location, err := homedir.Expand(userInput)
	if err != nil {
		return UnknownScheme, image.UnknownSource, "", fmt.Errorf("unable to expand potential directory path: %w", err)
	}

	fileMeta, err := fs.Stat(location)
	if err != nil {
		return UnknownScheme, source, "", nil
	}

	if fileMeta.IsDir() {
		return DirectoryScheme, source, location, nil
	}

	return FileScheme, source, location, nil
}
