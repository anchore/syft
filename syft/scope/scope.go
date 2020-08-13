/*
Package scope provides an abstraction to allow a user to loosely define a data source to catalog and expose a common interface that
catalogers and use explore and analyze data from the data source. All valid (cataloggable) data sources are defined
within this package.
*/
package scope

import (
	"fmt"
	"os"

	"github.com/anchore/stereoscope"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/scope/resolvers"
)

// ImageSource represents a data source that is a container image
type ImageSource struct {
	Img *image.Image // the image object to be cataloged
}

// DirSource represents a data source that is a filesystem directory tree
type DirSource struct {
	Path string // the root path to be cataloged
}

// Scope is an object that captures the data source to be cataloged, configuration, and a specific resolver used
// in cataloging (based on the data source and configuration)
type Scope struct {
	Option   Option      // specific perspective to catalog
	Resolver Resolver    // a Resolver object to use in file path/glob resolution and file contents resolution
	ImgSrc   ImageSource // the specific image to be cataloged
	DirSrc   DirSource   // the specific directory to be cataloged
}

// NewScope produces a Scope based on userInput like dir:// or image:tag
func NewScope(userInput string, o Option) (Scope, func(), error) {
	protocol := newProtocol(userInput)

	switch protocol.Type {
	case directoryProtocol:
		err := isValidPath(protocol.Value)
		if err != nil {
			return Scope{}, func() {}, fmt.Errorf("unable to process path, must exist and be a directory: %w", err)
		}

		s, err := NewScopeFromDir(protocol.Value)
		if err != nil {
			return Scope{}, func() {}, fmt.Errorf("could not populate scope from path (%s): %w", protocol.Value, err)
		}
		return s, func() {}, nil

	case imageProtocol:
		img, err := stereoscope.GetImage(userInput)
		cleanup := func() {
			stereoscope.Cleanup()
		}

		if err != nil || img == nil {
			return Scope{}, cleanup, fmt.Errorf("could not fetch image '%s': %w", userInput, err)
		}

		s, err := NewScopeFromImage(img, o)
		if err != nil {
			return Scope{}, cleanup, fmt.Errorf("could not populate scope with image: %w", err)
		}
		return s, cleanup, nil

	default:
		return Scope{}, func() {}, fmt.Errorf("unable to process input for scanning: '%s'", userInput)
	}
}

// NewScopeFromDir creates a new scope object tailored to catalog a given filesystem directory recursively.
func NewScopeFromDir(path string) (Scope, error) {
	return Scope{
		Resolver: &resolvers.DirectoryResolver{
			Path: path,
		},
		DirSrc: DirSource{
			Path: path,
		},
	}, nil
}

// NewScopeFromImage creates a new scope object tailored to catalog a given container image, relative to the
// option given (e.g. all-layers, squashed, etc)
func NewScopeFromImage(img *image.Image, option Option) (Scope, error) {
	if img == nil {
		return Scope{}, fmt.Errorf("no image given")
	}

	resolver, err := getImageResolver(img, option)
	if err != nil {
		return Scope{}, fmt.Errorf("could not determine file resolver: %w", err)
	}

	return Scope{
		Option:   option,
		Resolver: resolver,
		ImgSrc: ImageSource{
			Img: img,
		},
	}, nil
}

// Source returns the configured data source (either a dir source or container image source)
func (s Scope) Source() interface{} {
	if s.ImgSrc != (ImageSource{}) {
		return s.ImgSrc
	}
	if s.DirSrc != (DirSource{}) {
		return s.DirSrc
	}

	return nil
}

// isValidPath ensures that the user-provided input will correspond to a path that exists and is a directory
func isValidPath(userInput string) error {
	fileMeta, err := os.Stat(userInput)
	if err != nil {
		return err
	}

	if fileMeta.IsDir() {
		return nil
	}

	return fmt.Errorf("path is not a directory: %s", userInput)
}
