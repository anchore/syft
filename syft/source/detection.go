package source

import (
	"crypto"
	"fmt"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/afero"

	"github.com/anchore/stereoscope/pkg/image"
)

type Type string

const (
	// unknownType is the default scheme
	unknownType Type = "unknown-type"

	// DirectoryType indicates the source being cataloged is a directory on the root filesystem
	DirectoryType Type = "directory-type"

	// ContainerImageType indicates the source being cataloged is a container image
	ContainerImageType Type = "container-image-type"

	// FileType indicates the source being cataloged is a single file
	FileType Type = "file-type"
)

type sourceResolver func(string) (image.Source, string, error)

// Detection is an object that captures the detected user input regarding source location, scheme, and provider type.
// It acts as a struct input for some source constructors.
type Detection struct {
	Type        Type
	ImageSource image.Source
	Location    string
}

// Detect generates a source Detection that can be used as an argument to generate a new source
// from specific providers including a registry, with an explicit name.
func Detect(userInput string, defaultImageSource string) (*Detection, error) {
	fs := afero.NewOsFs()
	ty, src, location, err := detect(fs, image.DetectSource, userInput)
	if err != nil {
		return nil, err
	}

	if src == image.UnknownSource {
		// only run for these two schemes
		// only check on packages command, attest we automatically try to pull from userInput
		switch ty {
		case ContainerImageType, unknownType:
			ty = ContainerImageType
			location = userInput
			if defaultImageSource != "" {
				src = parseDefaultImageSource(defaultImageSource)
			} else {
				src = image.DetermineDefaultImagePullSource(userInput)
			}
		}
	}

	// collect user input for downstream consumption
	return &Detection{
		Type:        ty,
		ImageSource: src,
		Location:    location,
	}, nil
}

// NewSource produces a Source based on userInput like dir: or image:tag
func (in Detection) NewSource(
	alias *Alias,
	registryOptions *image.RegistryOptions,
	platformStr string,
	exclusions []string,
) (Source, error) {
	var err error
	var src Source

	if in.Type != ContainerImageType && platformStr != "" {
		return nil, fmt.Errorf("cannot specify a platform for a non-image source")
	}

	switch in.Type {
	case FileType:
		src, err = NewFromFile(
			FileConfig{
				Path: in.Location,
				Exclude: ExcludeConfig{
					Paths: exclusions,
				},
				DigestAlgorithms: []crypto.Hash{crypto.SHA256},
				Alias:            alias,
			},
		)
	case DirectoryType:
		src, err = NewFromDirectory(
			DirectoryConfig{
				Path: in.Location,
				Base: in.Location,
				Exclude: ExcludeConfig{
					Paths: exclusions,
				},
				Alias: alias,
			},
		)
	case ContainerImageType:
		var platform *image.Platform
		if platformStr != "" {
			platform, err = image.NewPlatform(platformStr)
			if err != nil {
				return nil, fmt.Errorf("unable to parse platform: %w", err)
			}
		}
		src, err = NewFromStereoscopeImage(
			StereoscopeImageConfig{
				Reference:       in.Location,
				From:            in.ImageSource,
				Platform:        platform,
				RegistryOptions: registryOptions,
				Exclude: ExcludeConfig{
					Paths: exclusions,
				},
				Alias: alias,
			},
		)
	default:
		err = fmt.Errorf("unable to process input for scanning")
	}

	return src, err
}

func detect(fs afero.Fs, imageSourceResolver sourceResolver, userInput string) (Type, image.Source, string, error) {
	switch {
	case strings.HasPrefix(userInput, "dir:"):
		dirLocation, err := homedir.Expand(strings.TrimPrefix(userInput, "dir:"))
		if err != nil {
			return unknownType, image.UnknownSource, "", fmt.Errorf("unable to expand directory path: %w", err)
		}
		return DirectoryType, image.UnknownSource, dirLocation, nil

	case strings.HasPrefix(userInput, "file:"):
		fileLocation, err := homedir.Expand(strings.TrimPrefix(userInput, "file:"))
		if err != nil {
			return unknownType, image.UnknownSource, "", fmt.Errorf("unable to expand directory path: %w", err)
		}
		return FileType, image.UnknownSource, fileLocation, nil
	}

	// try the most specific sources first and move out towards more generic sources.

	// first: let's try the image detector, which has more scheme parsing internal to stereoscope
	src, imageSpec, err := imageSourceResolver(userInput)
	if err == nil && src != image.UnknownSource {
		return ContainerImageType, src, imageSpec, nil
	}

	// next: let's try more generic sources (dir, file, etc.)
	location, err := homedir.Expand(userInput)
	if err != nil {
		return unknownType, image.UnknownSource, "", fmt.Errorf("unable to expand potential directory path: %w", err)
	}

	fileMeta, err := fs.Stat(location)
	if err != nil {
		return unknownType, src, "", nil
	}

	if fileMeta.IsDir() {
		return DirectoryType, src, location, nil
	}

	return FileType, src, location, nil
}

func parseDefaultImageSource(defaultImageSource string) image.Source {
	switch defaultImageSource {
	case "registry":
		return image.OciRegistrySource
	case "docker":
		return image.DockerDaemonSource
	case "podman":
		return image.PodmanDaemonSource
	default:
		return image.UnknownSource
	}
}
