package source

import (
	"crypto"
	"fmt"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/afero"

	"github.com/anchore/stereoscope/pkg/image"
)

type detectedType string

const (
	// unknownType is the default scheme
	unknownType detectedType = "unknown-type"

	// directoryType indicates the source being cataloged is a directory on the root filesystem
	directoryType detectedType = "directory-type"

	// containerImageType indicates the source being cataloged is a container image
	containerImageType detectedType = "container-image-type"

	// fileType indicates the source being cataloged is a single file
	fileType detectedType = "file-type"
)

type sourceResolver func(string) (image.Source, string, error)

// Detection is an object that captures the detected user input regarding source location, scheme, and provider type.
// It acts as a struct input for some source constructors.
type Detection struct {
	detectedType detectedType
	imageSource  image.Source
	location     string
}

func (d Detection) IsContainerImage() bool {
	return d.detectedType == containerImageType
}

type DetectConfig struct {
	DefaultImageSource string
}

func DefaultDetectConfig() DetectConfig {
	return DetectConfig{}
}

// Detect generates a source Detection that can be used as an argument to generate a new source
// from specific providers including a registry, with an explicit name.
func Detect(userInput string, cfg DetectConfig) (*Detection, error) {
	fs := afero.NewOsFs()
	ty, src, location, err := detect(fs, image.DetectSource, userInput)
	if err != nil {
		return nil, err
	}

	if src == image.UnknownSource {
		// only run for these two schemes
		// only check on scan command, attest we automatically try to pull from userInput
		switch ty {
		case containerImageType, unknownType:
			ty = containerImageType
			location = userInput
			if cfg.DefaultImageSource != "" {
				src = parseDefaultImageSource(cfg.DefaultImageSource)
			} else {
				src = image.DetermineDefaultImagePullSource(userInput)
			}
		}
	}

	// collect user input for downstream consumption
	return &Detection{
		detectedType: ty,
		imageSource:  src,
		location:     location,
	}, nil
}

type DetectionSourceConfig struct {
	Alias            Alias
	RegistryOptions  *image.RegistryOptions
	Platform         *image.Platform
	Exclude          ExcludeConfig
	DigestAlgorithms []crypto.Hash
	BasePath         string
}

func DefaultDetectionSourceConfig() DetectionSourceConfig {
	return DetectionSourceConfig{
		DigestAlgorithms: []crypto.Hash{
			crypto.SHA256,
		},
	}
}

// NewSource produces a Source based on userInput like dir: or image:tag
func (d Detection) NewSource(cfg DetectionSourceConfig) (Source, error) {
	var err error
	var src Source

	if d.detectedType != containerImageType && cfg.Platform != nil {
		return nil, fmt.Errorf("cannot specify a platform for a non-image source")
	}

	switch d.detectedType {
	case fileType:
		src, err = NewFromFile(
			FileConfig{
				Path:             d.location,
				Exclude:          cfg.Exclude,
				DigestAlgorithms: cfg.DigestAlgorithms,
				Alias:            cfg.Alias,
			},
		)
	case directoryType:
		base := cfg.BasePath
		if base == "" {
			base = d.location
		}
		src, err = NewFromDirectory(
			DirectoryConfig{
				Path:    d.location,
				Base:    base,
				Exclude: cfg.Exclude,
				Alias:   cfg.Alias,
			},
		)
	case containerImageType:
		src, err = NewFromStereoscopeImage(
			StereoscopeImageConfig{
				Reference:       d.location,
				From:            d.imageSource,
				Platform:        cfg.Platform,
				RegistryOptions: cfg.RegistryOptions,
				Exclude:         cfg.Exclude,
				Alias:           cfg.Alias,
			},
		)
	default:
		err = fmt.Errorf("unable to process input for scanning")
	}

	return src, err
}

func detect(fs afero.Fs, imageSourceResolver sourceResolver, userInput string) (detectedType, image.Source, string, error) {
	switch {
	case strings.HasPrefix(userInput, "dir:"):
		dirLocation, err := homedir.Expand(strings.TrimPrefix(userInput, "dir:"))
		if err != nil {
			return unknownType, image.UnknownSource, "", fmt.Errorf("unable to expand directory path: %w", err)
		}
		return directoryType, image.UnknownSource, dirLocation, nil

	case strings.HasPrefix(userInput, "file:"):
		fileLocation, err := homedir.Expand(strings.TrimPrefix(userInput, "file:"))
		if err != nil {
			return unknownType, image.UnknownSource, "", fmt.Errorf("unable to expand directory path: %w", err)
		}
		return fileType, image.UnknownSource, fileLocation, nil
	}

	// try the most specific sources first and move out towards more generic sources.

	// first: let's try the image detector, which has more scheme parsing internal to stereoscope
	src, imageSpec, err := imageSourceResolver(userInput)
	if err == nil && src != image.UnknownSource {
		return containerImageType, src, imageSpec, nil
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
		return directoryType, src, location, nil
	}

	return fileType, src, location, nil
}

func parseDefaultImageSource(defaultImageSource string) image.Source {
	switch defaultImageSource {
	case "registry":
		return image.OciRegistrySource
	case "docker":
		return image.DockerDaemonSource
	case "podman":
		return image.PodmanDaemonSource
	case "containerd":
		return image.ContainerdDaemonSource
	default:
		return image.UnknownSource
	}
}
