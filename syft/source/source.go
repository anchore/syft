/*
Package source provides an abstraction to allow a user to loosely define a data source to catalog and expose a common interface that
catalogers and use explore and analyze data from the data source. All valid (cataloggable) data sources are defined
within this package.
*/
package source

import (
	"fmt"

	"github.com/spf13/afero"

	"github.com/anchore/stereoscope"

	"github.com/anchore/stereoscope/pkg/image"
)

// Source is an object that captures the data source to be cataloged, configuration, and a specific resolver used
// in cataloging (based on the data source and configuration)
type Source struct {
	Resolver Resolver     // a Resolver object to use in file path/glob resolution and file contents resolution
	Image    *image.Image // the image object to be cataloged (image only)
	Metadata Metadata
}

type sourceDetector func(string) (image.Source, string, error)

// New produces a Source based on userInput like dir: or image:tag
func New(userInput string, o Scope) (Source, func(), error) {
	fs := afero.NewOsFs()
	parsedScheme, location, err := detectScheme(fs, image.DetectSource, userInput)
	if err != nil {
		return Source{}, func() {}, fmt.Errorf("unable to parse input=%q: %w", userInput, err)
	}

	switch parsedScheme {
	case DirectoryScheme:
		fileMeta, err := fs.Stat(location)
		if err != nil {
			return Source{}, func() {}, fmt.Errorf("unable to stat dir=%q: %w", location, err)
		}

		if !fileMeta.IsDir() {
			return Source{}, func() {}, fmt.Errorf("given path is not a directory (path=%q): %w", location, err)
		}

		s, err := NewFromDirectory(location)
		if err != nil {
			return Source{}, func() {}, fmt.Errorf("could not populate source from path=%q: %w", location, err)
		}
		return s, func() {}, nil

	case ImageScheme:
		img, err := stereoscope.GetImage(location)
		cleanup := func() {
			stereoscope.Cleanup()
		}

		if err != nil || img == nil {
			return Source{}, cleanup, fmt.Errorf("could not fetch image '%s': %w", location, err)
		}

		s, err := NewFromImage(img, o, location)
		if err != nil {
			return Source{}, cleanup, fmt.Errorf("could not populate source with image: %w", err)
		}
		return s, cleanup, nil
	}

	return Source{}, func() {}, fmt.Errorf("unable to process input for scanning: '%s'", userInput)
}

// NewFromDirectory creates a new source object tailored to catalog a given filesystem directory recursively.
func NewFromDirectory(path string) (Source, error) {
	return Source{
		Resolver: &DirectoryResolver{
			Path: path,
		},
		Metadata: Metadata{
			Scheme: DirectoryScheme,
			Path:   path,
		},
	}, nil
}

// NewFromImage creates a new source object tailored to catalog a given container image, relative to the
// option given (e.g. all-layers, squashed, etc)
func NewFromImage(img *image.Image, option Scope, userImageStr string) (Source, error) {
	if img == nil {
		return Source{}, fmt.Errorf("no image given")
	}

	resolver, err := getImageResolver(img, option)
	if err != nil {
		return Source{}, fmt.Errorf("could not determine file resolver: %w", err)
	}

	return Source{
		Resolver: resolver,
		Image:    img,
		Metadata: Metadata{
			Scope:         option,
			Scheme:        ImageScheme,
			ImageMetadata: NewImageMetadata(img, userImageStr),
		},
	}, nil
}
