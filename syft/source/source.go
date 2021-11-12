/*
Package source provides an abstraction to allow a user to loosely define a data source to catalog and expose a common interface that
catalogers and use explore and analyze data from the data source. All valid (cataloggable) data sources are defined
within this package.
*/
package source

import (
	"fmt"
	"sync"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/log"
	"github.com/spf13/afero"
)

// Source is an object that captures the data source to be cataloged, configuration, and a specific resolver used
// in cataloging (based on the data source and configuration)
type Source struct {
	Image             *image.Image // the image object to be cataloged (image only)
	DirectoryResolver *directoryResolver
	Metadata          Metadata
	Mutex             *sync.Mutex
}

type sourceDetector func(string) (image.Source, string, error)

// New produces a Source based on userInput like dir: or image:tag
func New(userInput string, registryOptions *image.RegistryOptions) (*Source, func(), error) {
	fs := afero.NewOsFs()
	parsedScheme, imageSource, location, err := detectScheme(fs, image.DetectSource, userInput)
	if err != nil {
		return &Source{}, func() {}, fmt.Errorf("unable to parse input=%q: %w", userInput, err)
	}

	switch parsedScheme {
	case FileScheme:
		return generateFileSource(fs, location)
	case DirectoryScheme:
		return generateDirectorySource(fs, location)
	case ImageScheme:
		return generateImageSource(location, userInput, imageSource, registryOptions)
	}

	return &Source{}, func() {}, fmt.Errorf("unable to process input for scanning: '%s'", userInput)
}

func generateImageSource(location, userInput string, imageSource image.Source, registryOptions *image.RegistryOptions) (*Source, func(), error) {
	img, err := stereoscope.GetImageFromSource(location, imageSource, registryOptions)
	if err != nil {
		log.Debugf("error parsing location: %s after detecting scheme; pulling image: %s", location, userInput)
		// we may have been to aggressive reading the source hint
		// try the input as supplied by the user if our initial parse failed
		img, err = stereoscope.GetImageFromSource(userInput, imageSource, registryOptions)
	}

	cleanup := stereoscope.Cleanup

	if err != nil || img == nil {
		return &Source{}, cleanup, fmt.Errorf("could not fetch image '%s': %w", location, err)
	}

	s, err := NewFromImage(img, location)
	if err != nil {
		return &Source{}, cleanup, fmt.Errorf("could not populate source with image: %w", err)
	}

	return &s, cleanup, nil
}

func generateDirectorySource(fs afero.Fs, location string) (*Source, func(), error) {
	fileMeta, err := fs.Stat(location)
	if err != nil {
		return &Source{}, func() {}, fmt.Errorf("unable to stat dir=%q: %w", location, err)
	}

	if !fileMeta.IsDir() {
		return &Source{}, func() {}, fmt.Errorf("given path is not a directory (path=%q): %w", location, err)
	}

	s, err := NewFromDirectory(location)
	if err != nil {
		return &Source{}, func() {}, fmt.Errorf("could not populate source from path=%q: %w", location, err)
	}

	return &s, func() {}, nil
}

func generateFileSource(fs afero.Fs, location string) (*Source, func(), error) {
	fileMeta, err := fs.Stat(location)
	if err != nil {
		return &Source{}, func() {}, fmt.Errorf("unable to stat dir=%q: %w", location, err)
	}

	if fileMeta.IsDir() {
		return &Source{}, func() {}, fmt.Errorf("given path is not a directory (path=%q): %w", location, err)
	}

	s, err := NewFromFile(location)
	if err != nil {
		return &Source{}, func() {}, fmt.Errorf("could not populate source from path=%q: %w", location, err)
	}

	return &s, func() {}, nil
}

// NewFromDirectory creates a new source object tailored to catalog a given filesystem directory recursively.
func NewFromDirectory(path string) (Source, error) {
	return Source{
		Mutex: &sync.Mutex{},
		Metadata: Metadata{
			Scheme: DirectoryScheme,
			Path:   path,
		},
	}, nil
}

// NewFromDirectory creates a new source object tailored to catalog a given filesystem directory recursively.
func NewFromFile(path string) (Source, error) {
	return Source{
		Mutex: &sync.Mutex{},
		Metadata: Metadata{
			Scheme: FileScheme,
			Path:   path,
		},
	}, nil
}

// NewFromImage creates a new source object tailored to catalog a given container image, relative to the
// option given (e.g. all-layers, squashed, etc)
func NewFromImage(img *image.Image, userImageStr string) (Source, error) {
	if img == nil {
		return Source{}, fmt.Errorf("no image given")
	}

	return Source{
		Image: img,
		Metadata: Metadata{
			Scheme:        ImageScheme,
			ImageMetadata: NewImageMetadata(img, userImageStr),
		},
	}, nil
}

func (s *Source) FileResolver(scope Scope) (FileResolver, error) {
	switch s.Metadata.Scheme {
	case DirectoryScheme, FileScheme:
		s.Mutex.Lock()
		defer s.Mutex.Unlock()
		if s.DirectoryResolver == nil {
			resolver, err := newDirectoryResolver(s.Metadata.Path)
			if err != nil {
				return nil, err
			}
			s.DirectoryResolver = resolver
		}
		return s.DirectoryResolver, nil
	case ImageScheme:
		switch scope {
		case SquashedScope:
			return newImageSquashResolver(s.Image)
		case AllLayersScope:
			return newAllLayersResolver(s.Image)
		default:
			return nil, fmt.Errorf("bad image scope provided: %+v", scope)
		}
	}
	return nil, fmt.Errorf("unable to determine FilePathResolver with current scheme=%q", s.Metadata.Scheme)
}
