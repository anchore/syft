/*
Package source provides an abstraction to allow a user to loosely define a data source to catalog and expose a common interface that
catalogers and use explore and analyze data from the data source. All valid (cataloggable) data sources are defined
within this package.
*/
package source

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/mholt/archiver/v3"
	digest "github.com/opencontainers/go-digest"
	"github.com/spf13/afero"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
)

// Source is an object that captures the data source to be cataloged, configuration, and a specific resolver used
// in cataloging (based on the data source and configuration)
type Source struct {
	id                artifact.ID  `hash:"ignore"`
	Image             *image.Image `hash:"ignore"` // the image object to be cataloged (image only)
	Metadata          Metadata
	directoryResolver *fileresolver.Directory `hash:"ignore"`
	path              string
	base              string
	mutex             *sync.Mutex
	Exclusions        []string `hash:"ignore"`
}

// Input is an object that captures the detected user input regarding source location, scheme, and provider type.
// It acts as a struct input for some source constructors.
type Input struct {
	UserInput   string
	Scheme      Scheme
	ImageSource image.Source
	Location    string
	Platform    string
	Name        string
	Version     string
}

// ParseInput generates a source Input that can be used as an argument to generate a new source
// from specific providers including a registry.
func ParseInput(userInput string, platform string) (*Input, error) {
	return ParseInputWithName(userInput, platform, "", "")
}

// ParseInputWithName generates a source Input that can be used as an argument to generate a new source
// from specific providers including a registry, with an explicit name.
func ParseInputWithName(userInput string, platform, name, defaultImageSource string) (*Input, error) {
	return ParseInputWithNameVersion(userInput, platform, name, "", defaultImageSource)
}

// ParseInputWithNameVersion generates a source Input that can be used as an argument to generate a new source
// from specific providers including a registry, with an explicit name and version.
func ParseInputWithNameVersion(userInput, platform, name, version, defaultImageSource string) (*Input, error) {
	fs := afero.NewOsFs()
	scheme, source, location, err := DetectScheme(fs, image.DetectSource, userInput)
	if err != nil {
		return nil, err
	}

	if source == image.UnknownSource {
		// only run for these two scheme
		// only check on packages command, attest we automatically try to pull from userInput
		switch scheme {
		case ImageScheme, UnknownScheme:
			scheme = ImageScheme
			location = userInput
			if defaultImageSource != "" {
				source = parseDefaultImageSource(defaultImageSource)
			} else {
				imagePullSource := image.DetermineDefaultImagePullSource(userInput)
				source = imagePullSource
			}
			if location == "" {
				location = userInput
			}
		default:
		}
	}

	if scheme != ImageScheme && platform != "" {
		return nil, fmt.Errorf("cannot specify a platform for a non-image source")
	}

	// collect user input for downstream consumption
	return &Input{
		UserInput:   userInput,
		Scheme:      scheme,
		ImageSource: source,
		Location:    location,
		Platform:    platform,
		Name:        name,
		Version:     version,
	}, nil
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

type sourceDetector func(string) (image.Source, string, error)

func NewFromRegistry(in Input, registryOptions *image.RegistryOptions, exclusions []string) (*Source, func(), error) {
	source, cleanupFn, err := generateImageSource(in, registryOptions)
	if source != nil {
		source.Exclusions = exclusions
	}
	return source, cleanupFn, err
}

// New produces a Source based on userInput like dir: or image:tag
func New(in Input, registryOptions *image.RegistryOptions, exclusions []string) (*Source, func(), error) {
	var err error
	fs := afero.NewOsFs()
	var source *Source
	cleanupFn := func() {}

	switch in.Scheme {
	case FileScheme:
		source, cleanupFn, err = generateFileSource(fs, in)
	case DirectoryScheme:
		source, cleanupFn, err = generateDirectorySource(fs, in)
	case ImageScheme:
		source, cleanupFn, err = generateImageSource(in, registryOptions)
	default:
		err = fmt.Errorf("unable to process input for scanning: %q", in.UserInput)
	}

	if err == nil {
		source.Exclusions = exclusions
	}

	return source, cleanupFn, err
}

func generateImageSource(in Input, registryOptions *image.RegistryOptions) (*Source, func(), error) {
	img, cleanup, err := getImageWithRetryStrategy(in, registryOptions)
	if err != nil || img == nil {
		return nil, cleanup, fmt.Errorf("could not fetch image %q: %w", in.Location, err)
	}

	s, err := NewFromImageWithNameVersion(img, in.Location, in.Name, in.Version)
	if err != nil {
		return nil, cleanup, fmt.Errorf("could not populate source with image: %w", err)
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

func getImageWithRetryStrategy(in Input, registryOptions *image.RegistryOptions) (*image.Image, func(), error) {
	ctx := context.TODO()

	var opts []stereoscope.Option
	if registryOptions != nil {
		opts = append(opts, stereoscope.WithRegistryOptions(*registryOptions))
	}

	if in.Platform != "" {
		opts = append(opts, stereoscope.WithPlatform(in.Platform))
	}

	img, err := stereoscope.GetImageFromSource(ctx, in.Location, in.ImageSource, opts...)
	cleanup := func() {
		if err := img.Cleanup(); err != nil {
			log.Warnf("unable to cleanup image=%q: %w", in.UserInput, err)
		}
	}
	if err == nil {
		// Success on the first try!
		return img, cleanup, nil
	}

	scheme := parseScheme(in.UserInput)
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
		in.UserInput,
		err,
	)

	// We need to determine the image source again, such that this determination
	// doesn't take scheme parsing into account.
	in.ImageSource = image.DetermineDefaultImagePullSource(in.UserInput)
	img, userInputErr := stereoscope.GetImageFromSource(ctx, in.UserInput, in.ImageSource, opts...)
	cleanup = func() {
		if err := img.Cleanup(); err != nil {
			log.Warnf("unable to cleanup image=%q: %w", in.UserInput, err)
		}
	}
	if userInputErr != nil {
		// Image retrieval failed on both tries, we will want to return both errors.
		return nil, nil, fmt.Errorf(
			"scheme %q specified; "+
				"image retrieval using scheme parsing (%s) was unsuccessful: %v; "+
				"image retrieval without scheme parsing (%s) was unsuccessful: %v",
			scheme,
			in.Location,
			err,
			in.UserInput,
			userInputErr,
		)
	}

	return img, cleanup, nil
}

func generateDirectorySource(fs afero.Fs, in Input) (*Source, func(), error) {
	fileMeta, err := fs.Stat(in.Location)
	if err != nil {
		return nil, func() {}, fmt.Errorf("unable to stat dir=%q: %w", in.Location, err)
	}

	if !fileMeta.IsDir() {
		return nil, func() {}, fmt.Errorf("given path is not a directory (path=%q): %w", in.Location, err)
	}

	s, err := NewFromDirectoryWithNameVersion(in.Location, in.Name, in.Version)
	if err != nil {
		return nil, func() {}, fmt.Errorf("could not populate source from path=%q: %w", in.Location, err)
	}

	return &s, func() {}, nil
}

func generateFileSource(fs afero.Fs, in Input) (*Source, func(), error) {
	fileMeta, err := fs.Stat(in.Location)
	if err != nil {
		return nil, func() {}, fmt.Errorf("unable to stat dir=%q: %w", in.Location, err)
	}

	if fileMeta.IsDir() {
		return nil, func() {}, fmt.Errorf("given path is not a directory (path=%q): %w", in.Location, err)
	}

	s, cleanupFn := NewFromFileWithNameVersion(in.Location, in.Name, in.Version)

	return &s, cleanupFn, nil
}

// NewFromDirectory creates a new source object tailored to catalog a given filesystem directory recursively.
func NewFromDirectory(path string) (Source, error) {
	return NewFromDirectoryWithName(path, "")
}

// NewFromDirectoryWithName creates a new source object tailored to catalog a given filesystem directory recursively, with an explicitly provided name.
func NewFromDirectoryWithName(path string, name string) (Source, error) {
	return NewFromDirectoryWithNameVersion(path, name, "")
}

// NewFromDirectoryWithNameVersion creates a new source object tailored to catalog a given filesystem directory recursively, with an explicitly provided name.
func NewFromDirectoryWithNameVersion(path string, name string, version string) (Source, error) {
	s := Source{
		mutex: &sync.Mutex{},
		Metadata: Metadata{
			Name:    name,
			Version: version,
			Scheme:  DirectoryScheme,
			Path:    path,
		},
		path: path,
	}
	s.SetID()
	return s, nil
}

// NewFromDirectoryRoot creates a new source object tailored to catalog a given filesystem directory recursively.
func NewFromDirectoryRoot(path string) (Source, error) {
	return NewFromDirectoryRootWithName(path, "")
}

// NewFromDirectoryRootWithName creates a new source object tailored to catalog a given filesystem directory recursively, with an explicitly provided name.
func NewFromDirectoryRootWithName(path string, name string) (Source, error) {
	return NewFromDirectoryRootWithNameVersion(path, name, "")
}

// NewFromDirectoryRootWithNameVersion creates a new source object tailored to catalog a given filesystem directory recursively, with an explicitly provided name.
func NewFromDirectoryRootWithNameVersion(path string, name string, version string) (Source, error) {
	s := Source{
		mutex: &sync.Mutex{},
		Metadata: Metadata{
			Name:    name,
			Version: version,
			Scheme:  DirectoryScheme,
			Path:    path,
			Base:    path,
		},
		path: path,
		base: path,
	}
	s.SetID()
	return s, nil
}

// NewFromFile creates a new source object tailored to catalog a file.
func NewFromFile(path string) (Source, func()) {
	return NewFromFileWithName(path, "")
}

// NewFromFileWithName creates a new source object tailored to catalog a file, with an explicitly provided name.
func NewFromFileWithName(path string, name string) (Source, func()) {
	return NewFromFileWithNameVersion(path, name, "")
}

// NewFromFileWithNameVersion creates a new source object tailored to catalog a file, with an explicitly provided name and version.
func NewFromFileWithNameVersion(path string, name string, version string) (Source, func()) {
	analysisPath, cleanupFn := fileAnalysisPath(path)

	s := Source{
		mutex: &sync.Mutex{},
		Metadata: Metadata{
			Name:    name,
			Version: version,
			Scheme:  FileScheme,
			Path:    path,
		},
		path: analysisPath,
	}

	s.SetID()
	return s, cleanupFn
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
		if tar, ok := unarchiver.(*archiver.Tar); ok {
			// when tar files are extracted, if there are multiple entries at the same
			// location, the last entry wins
			// NOTE: this currently does not display any messages if an overwrite happens
			tar.OverwriteExisting = true
		}
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
	return NewFromImageWithName(img, userImageStr, "")
}

// NewFromImageWithName creates a new source object tailored to catalog a given container image, relative to the
// option given (e.g. all-layers, squashed, etc), with an explicit name.
func NewFromImageWithName(img *image.Image, userImageStr string, name string) (Source, error) {
	return NewFromImageWithNameVersion(img, userImageStr, name, "")
}

// NewFromImageWithNameVersion creates a new source object tailored to catalog a given container image, relative to the
// option given (e.g. all-layers, squashed, etc), with an explicit name and version.
func NewFromImageWithNameVersion(img *image.Image, userImageStr string, name string, version string) (Source, error) {
	if img == nil {
		return Source{}, fmt.Errorf("no image given")
	}

	s := Source{
		Image: img,
		Metadata: Metadata{
			Name:          name,
			Version:       version,
			Scheme:        ImageScheme,
			ImageMetadata: NewImageMetadata(img, userImageStr),
		},
	}
	s.SetID()
	return s, nil
}

func (s *Source) ID() artifact.ID {
	if s.id == "" {
		s.SetID()
	}
	return s.id
}

func (s *Source) SetID() {
	var d string
	switch s.Metadata.Scheme {
	case DirectoryScheme:
		d = digest.FromString(s.Metadata.Path).String()
	case FileScheme:
		// attempt to use the digest of the contents of the file as the ID
		file, err := os.Open(s.Metadata.Path)
		if err != nil {
			d = digest.FromString(s.Metadata.Path).String()
			break
		}
		defer file.Close()
		di, err := digest.FromReader(file)
		if err != nil {
			d = digest.FromString(s.Metadata.Path).String()
			break
		}
		d = di.String()
	case ImageScheme:
		manifestDigest := digest.FromBytes(s.Metadata.ImageMetadata.RawManifest).String()
		if manifestDigest != "" {
			d = manifestDigest
			break
		}

		// calcuate chain ID for image sources where manifestDigest is not available
		// https://github.com/opencontainers/image-spec/blob/main/config.md#layer-chainid
		d = calculateChainID(s.Metadata.ImageMetadata.Layers)
		if d == "" {
			// TODO what happens here if image has no layers?
			// Is this case possible
			d = digest.FromString(s.Metadata.ImageMetadata.UserInput).String()
		}
	default: // for UnknownScheme we hash the struct
		id, _ := artifact.IDByHash(s)
		d = string(id)
	}

	s.id = artifact.ID(strings.TrimPrefix(d, "sha256:"))
	s.Metadata.ID = strings.TrimPrefix(d, "sha256:")
}

func calculateChainID(lm []LayerMetadata) string {
	if len(lm) < 1 {
		return ""
	}

	// DiffID(L0) = digest of layer 0
	// https://github.com/anchore/stereoscope/blob/1b1b744a919964f38d14e1416fb3f25221b761ce/pkg/image/layer_metadata.go#L19-L32
	chainID := lm[0].Digest
	id := chain(chainID, lm[1:])

	return id
}

func chain(chainID string, layers []LayerMetadata) string {
	if len(layers) < 1 {
		return chainID
	}

	chainID = digest.FromString(layers[0].Digest + " " + chainID).String()
	return chain(chainID, layers[1:])
}

func (s *Source) FileResolver(scope Scope) (file.Resolver, error) {
	switch s.Metadata.Scheme {
	case DirectoryScheme, FileScheme:
		s.mutex.Lock()
		defer s.mutex.Unlock()
		if s.directoryResolver == nil {
			exclusionFunctions, err := getDirectoryExclusionFunctions(s.path, s.Exclusions)
			if err != nil {
				return nil, err
			}
			res, err := fileresolver.NewFromDirectory(s.path, s.base, exclusionFunctions...)
			if err != nil {
				return nil, fmt.Errorf("unable to create directory resolver: %w", err)
			}
			s.directoryResolver = res
		}
		return s.directoryResolver, nil
	case ImageScheme:
		var res file.Resolver
		var err error
		switch scope {
		case SquashedScope:
			res, err = fileresolver.NewFromContainerImageSquash(s.Image)
		case AllLayersScope:
			res, err = fileresolver.NewFromContainerImageAllLayers(s.Image)
		default:
			return nil, fmt.Errorf("bad image scope provided: %+v", scope)
		}
		if err != nil {
			return nil, err
		}
		// image tree contains all paths, so we filter out the excluded entries afterwards
		if len(s.Exclusions) > 0 {
			res = fileresolver.NewExcluding(res, getImageExclusionFunction(s.Exclusions))
		}
		return res, nil
	}
	return nil, fmt.Errorf("unable to determine FilePathResolver with current scheme=%q", s.Metadata.Scheme)
}

func unarchiveToTmp(path string, unarchiver archiver.Unarchiver) (string, func(), error) {
	tempDir, err := os.MkdirTemp("", "syft-archive-contents-")
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

func getDirectoryExclusionFunctions(root string, exclusions []string) ([]fileresolver.PathIndexVisitor, error) {
	if len(exclusions) == 0 {
		return nil, nil
	}

	// this is what Directory.indexTree is doing to get the absolute path:
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	// this handles Windows file paths by converting them to C:/something/else format
	root = filepath.ToSlash(root)

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

	return []fileresolver.PathIndexVisitor{
		func(path string, info os.FileInfo, _ error) error {
			for _, exclusion := range exclusions {
				// this is required to handle Windows filepaths
				path = filepath.ToSlash(path)
				matches, err := doublestar.Match(exclusion, path)
				if err != nil {
					return nil
				}
				if matches {
					if info != nil && info.IsDir() {
						return filepath.SkipDir
					}
					return fileresolver.ErrSkipPath
				}
			}
			return nil
		},
	}, nil
}
