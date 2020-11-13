package source

import (
	"fmt"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/afero"
)

type Scheme string

const (
	UnknownScheme   Scheme = "unknown-scheme"
	DirectoryScheme Scheme = "directory-scheme"
	ImageScheme     Scheme = "image-scheme"
)

func detectScheme(fs afero.Fs, imageDetector sourceDetector, userInput string) (Scheme, string, error) {
	if strings.HasPrefix(userInput, "dir:") {
		// blindly trust the user's scheme
		dirLocation, err := homedir.Expand(strings.TrimPrefix(userInput, "dir:"))
		if err != nil {
			return UnknownScheme, "", fmt.Errorf("unable to expand directory path: %w", err)
		}
		return DirectoryScheme, dirLocation, nil
	}

	// we should attempt to let stereoscope determine what the source is first --just because the source is a valid directory
	// doesn't mean we yet know if it is an OCI layout directory (to be treated as an image) or if it is a generic filesystem directory.
	source, imageSpec, err := imageDetector(userInput)
	if err != nil {
		return UnknownScheme, "", fmt.Errorf("unable to detect the scheme from %q: %w", userInput, err)
	}

	if source == image.UnknownSource {
		dirLocation, err := homedir.Expand(userInput)
		if err != nil {
			return UnknownScheme, "", fmt.Errorf("unable to expand potential directory path: %w", err)
		}

		fileMeta, err := fs.Stat(dirLocation)
		if err != nil {
			return UnknownScheme, "", nil
		}

		if fileMeta.IsDir() {
			return DirectoryScheme, dirLocation, nil
		}
		return UnknownScheme, "", nil
	}

	return ImageScheme, imageSpec, nil
}
