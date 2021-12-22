/*
Package source provides an abstraction to allow a user to loosely define a data source to catalog and expose a common interface that
catalogers and use explore and analyze data from the data source. All valid (cataloggable) data sources are defined
within this package.
*/
package source

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/log"
	"github.com/bmatcuk/doublestar/v2"
	"github.com/mholt/archiver/v3"
	"github.com/spf13/afero"
)

// Source is an object that captures the data source to be cataloged, configuration, and a specific resolver used
// in cataloging (based on the data source and configuration)
type Source struct {
	Image             *image.Image // the image object to be cataloged (image only)
	Metadata          Metadata
	directoryResolver *directoryResolver
	path              string
	mutex             *sync.Mutex
	Exclusions        []string
}

type sourceDetector func(string) (image.Source, string, error)

// New produces a Source based on userInput like dir: or image:tag
func New(userInput string, registryOptions *image.RegistryOptions, exclusions ...string) (*Source, func(), error) {
	fs := afero.NewOsFs()
	parsedScheme, imageSource, location, err := detectScheme(fs, image.DetectSource, userInput)
	if err != nil {
		return &Source{}, func() {}, fmt.Errorf("unable to parse input=%q: %w", userInput, err)
	}

	source := &Source{}
	cleanupFn := func() {}

	switch parsedScheme {
	case FileScheme:
		source, cleanupFn, err = generateFileSource(fs, location)
	case DirectoryScheme:
		source, cleanupFn, err = generateDirectorySource(fs, location)
	case ImageScheme:
		source, cleanupFn, err = generateImageSource(userInput, location, imageSource, registryOptions)
	default:
		err = fmt.Errorf("unable to process input for scanning: '%s'", userInput)
	}

	if err == nil {
		source.Exclusions = exclusions
	}

	return source, cleanupFn, err
}

func generateImageSource(userInput, location string, imageSource image.Source, registryOptions *image.RegistryOptions) (*Source, func(), error) {
	img, cleanup, err := getImageWithRetryStrategy(userInput, location, imageSource, registryOptions)
	if err != nil || img == nil {
		return &Source{}, cleanup, fmt.Errorf("could not fetch image '%s': %w", location, err)
	}

	s, err := NewFromImage(img, location)
	if err != nil {
		return &Source{}, cleanup, fmt.Errorf("could not populate source with image: %w", err)
	}

	return &s, cleanup, nil
}

func parseScheme(userInput string) string {
	parts := strings.SplitN(userInput, ":", 2)
	if len(parts) < 2 {
		return ""
	}

	return parts[0]
}

func getImageWithRetryStrategy(userInput, location string, imageSource image.Source, registryOptions *image.RegistryOptions) (*image.Image, func(), error) {
	img, err := stereoscope.GetImageFromSource(location, imageSource, registryOptions)
	if err == nil {
		// Success on the first try!
		return img, stereoscope.Cleanup, nil
	}

	scheme := parseScheme(userInput)
	if !(scheme == "docker" || scheme == "registry") {
		// Image retrieval failed, and we shouldn't retry it. It's most likely that the
		// user _did_ intend the parsed scheme, but there was a legitimate failure with
		// using the scheme to load the image. Alert the user to this failure, so they
		// can fix the problem.
		return nil, nil, err
	}

	// Maybe the user wanted "docker" or "registry" to refer to an _image name_
	// (e.g. "docker:latest"), not a scheme. We'll retry image retrieval with this
	// alternative interpretation, in an attempt to avoid unnecessary user friction.

	log.Warnf(
		"scheme %q specified, but it coincides with a common image name; re-examining user input %q"+
			" without scheme parsing because image retrieval using scheme parsing was unsuccessful: %v",
		scheme,
		userInput,
		err,
	)

	imageSource = image.DetermineImagePullSource(userInput)
	img, err = stereoscope.GetImageFromSource(userInput, imageSource, registryOptions)
	if err != nil {
		return nil, nil, err
	}

	return img, stereoscope.Cleanup, nil
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

	s, cleanupFn := NewFromFile(location)

	return &s, cleanupFn, nil
}

// NewFromDirectory creates a new source object tailored to catalog a given filesystem directory recursively.
func NewFromDirectory(path string) (Source, error) {
	return Source{
		mutex: &sync.Mutex{},
		Metadata: Metadata{
			Scheme: DirectoryScheme,
			Path:   path,
		},
		path: path,
	}, nil
}

// NewFromFile creates a new source object tailored to catalog a file.
func NewFromFile(path string) (Source, func()) {
	analysisPath, cleanupFn := fileAnalysisPath(path)

	return Source{
		mutex: &sync.Mutex{},
		Metadata: Metadata{
			Scheme: FileScheme,
			Path:   path,
		},
		path: analysisPath,
	}, cleanupFn
}

// fileAnalysisPath returns the path given, or in the case the path is an archive, the location where the archive
// contents have been made available. A cleanup function is provided for any temp files created (if any).
func fileAnalysisPath(path string) (string, func()) {
	var analysisPath = path
	var cleanupFn = func() {}

	// if the given file is an archive (as indicated by the file extension and not MIME type) then unarchive it and
	// use the contents as the source. Note: this does NOT recursively unarchive contents, only the given path is
	// unarchived.
	envelopedUnarchiver, err := archiver.ByExtension(path)
	if unarchiver, ok := envelopedUnarchiver.(archiver.Unarchiver); err == nil && ok {
		unarchivedPath, tmpCleanup, err := unarchiveToTmp(path, unarchiver)
		if err != nil {
			log.Warnf("file could not be unarchived: %+v", err)
		} else {
			log.Debugf("source path is an archive")
			analysisPath = unarchivedPath
		}
		if tmpCleanup != nil {
			cleanupFn = tmpCleanup
		}
	}

	return analysisPath, cleanupFn
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
		s.mutex.Lock()
		defer s.mutex.Unlock()
		if s.directoryResolver == nil {
			exclusionFunctions, err := getDirectoryExclusionFunctions(s.path, s.Exclusions)
			if err != nil {
				return nil, err
			}
			resolver, err := newDirectoryResolver(s.path, exclusionFunctions...)
			if err != nil {
				return nil, err
			}
			s.directoryResolver = resolver
		}
		return s.directoryResolver, nil
	case ImageScheme:
		var resolver FileResolver
		var err error
		switch scope {
		case SquashedScope:
			resolver, err = newImageSquashResolver(s.Image)
		case AllLayersScope:
			resolver, err = newAllLayersResolver(s.Image)
		default:
			return nil, fmt.Errorf("bad image scope provided: %+v", scope)
		}
		if err != nil {
			return nil, err
		}
		// image tree contains all paths, so we filter out the excluded entries afterwards
		if len(s.Exclusions) > 0 {
			resolver = NewExcludingResolver(resolver, getImageExclusionFunction(s.Exclusions))
		}
		return resolver, nil
	}
	return nil, fmt.Errorf("unable to determine FilePathResolver with current scheme=%q", s.Metadata.Scheme)
}

func unarchiveToTmp(path string, unarchiver archiver.Unarchiver) (string, func(), error) {
	tempDir, err := ioutil.TempDir("", "syft-archive-contents-")
	if err != nil {
		return "", func() {}, fmt.Errorf("unable to create tempdir for archive processing: %w", err)
	}

	cleanupFn := func() {
		if err := os.RemoveAll(tempDir); err != nil {
			log.Warnf("unable to cleanup archive tempdir: %+v", err)
		}
	}

	return tempDir, cleanupFn, unarchiver.Unarchive(path, tempDir)
}

func getImageExclusionFunction(exclusions []string) func(string) bool {
	if len(exclusions) == 0 {
		return nil
	}
	// add subpath exclusions
	for _, exclusion := range exclusions {
		exclusions = append(exclusions, exclusion+"/**")
	}
	return func(path string) bool {
		for _, exclusion := range exclusions {
			matches, err := doublestar.Match(exclusion, path)
			if err != nil {
				return false
			}
			if matches {
				return true
			}
		}
		return false
	}
}

func getDirectoryExclusionFunctions(root string, exclusions []string) ([]pathFilterFn, error) {
	if len(exclusions) == 0 {
		return nil, nil
	}

	// this is what directoryResolver.indexTree is doing to get the absolute path:
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	if !strings.HasSuffix(root, "/") {
		root += "/"
	}

	var errors []string
	for idx, exclusion := range exclusions {
		// check exclusions for supported paths, these are all relative to the "scan root"
		if strings.HasPrefix(exclusion, "./") || strings.HasPrefix(exclusion, "*/") || strings.HasPrefix(exclusion, "**/") {
			exclusion = strings.TrimPrefix(exclusion, "./")
			exclusions[idx] = root + exclusion
		} else {
			errors = append(errors, exclusion)
		}
	}

	if errors != nil {
		return nil, fmt.Errorf("invalid exclusion pattern(s): '%s' (must start with one of: './', '*/', or '**/')", strings.Join(errors, "', '"))
	}

	return []pathFilterFn{
		func(path string, _ os.FileInfo) bool {
			for _, exclusion := range exclusions {
				matches, err := doublestar.Match(exclusion, path)
				if err != nil {
					return false
				}
				if matches {
					return true
				}
			}
			return false
		},
	}, nil
}
