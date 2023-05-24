package fileresolver

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

const WindowsOS = "windows"

var unixSystemRuntimePrefixes = []string{
	"/proc",
	"/dev",
	"/sys",
}

var ErrSkipPath = errors.New("skip path")

var _ file.Resolver = (*Directory)(nil)

// Directory implements path and content access for the directory data source.
type Directory struct {
	path                    string
	base                    string
	currentWdRelativeToRoot string
	currentWd               string
	tree                    filetree.Reader
	index                   filetree.IndexReader
	searchContext           filetree.Searcher
	indexer                 *directoryIndexer
}

func NewFromDirectory(root string, base string, pathFilters ...PathIndexVisitor) (*Directory, error) {
	r, err := newFromDirectoryWithoutIndex(root, base, pathFilters...)
	if err != nil {
		return nil, err
	}

	return r, r.buildIndex()
}

func newFromDirectoryWithoutIndex(root string, base string, pathFilters ...PathIndexVisitor) (*Directory, error) {
	currentWD, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("could not get CWD: %w", err)
	}

	cleanRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("could not evaluate root=%q symlinks: %w", root, err)
	}

	cleanBase := ""
	if base != "" {
		cleanBase, err = filepath.EvalSymlinks(base)
		if err != nil {
			return nil, fmt.Errorf("could not evaluate base=%q symlinks: %w", base, err)
		}
		cleanBase, err = filepath.Abs(cleanBase)
		if err != nil {
			return nil, err
		}
	}

	var currentWdRelRoot string
	if path.IsAbs(cleanRoot) {
		currentWdRelRoot, err = filepath.Rel(currentWD, cleanRoot)
		if err != nil {
			return nil, fmt.Errorf("could not determine given root path to CWD: %w", err)
		}
	} else {
		currentWdRelRoot = filepath.Clean(cleanRoot)
	}

	return &Directory{
		path:                    cleanRoot,
		base:                    cleanBase,
		currentWd:               currentWD,
		currentWdRelativeToRoot: currentWdRelRoot,
		tree:                    filetree.New(),
		index:                   filetree.NewIndex(),
		indexer:                 newDirectoryIndexer(cleanRoot, cleanBase, pathFilters...),
	}, nil
}

func (r *Directory) buildIndex() error {
	if r.indexer == nil {
		return fmt.Errorf("no directory indexer configured")
	}
	tree, index, err := r.indexer.build()
	if err != nil {
		return err
	}

	r.tree = tree
	r.index = index
	r.searchContext = filetree.NewSearchContext(tree, index)

	return nil
}

func (r Directory) requestPath(userPath string) (string, error) {
	if filepath.IsAbs(userPath) {
		// don't allow input to potentially hop above root path
		userPath = path.Join(r.path, userPath)
	} else {
		// ensure we take into account any relative difference between the root path and the CWD for relative requests
		userPath = path.Join(r.currentWdRelativeToRoot, userPath)
	}

	var err error
	userPath, err = filepath.Abs(userPath)
	if err != nil {
		return "", err
	}
	return userPath, nil
}

// responsePath takes a path from the underlying fs domain and converts it to a path that is relative to the root of the directory resolver.
func (r Directory) responsePath(path string) string {
	// check to see if we need to encode back to Windows from posix
	if runtime.GOOS == WindowsOS {
		path = posixToWindows(path)
	}

	// clean references to the request path (either the root, or the base if set)
	if filepath.IsAbs(path) {
		var prefix string
		if r.base != "" {
			prefix = r.base
		} else {
			// we need to account for the cwd relative to the running process and the given root for the directory resolver
			prefix = filepath.Clean(filepath.Join(r.currentWd, r.currentWdRelativeToRoot))
			prefix += string(filepath.Separator)
		}
		path = strings.TrimPrefix(path, prefix)
	}

	return path
}

// HasPath indicates if the given path exists in the underlying source.
func (r *Directory) HasPath(userPath string) bool {
	requestPath, err := r.requestPath(userPath)
	if err != nil {
		return false
	}
	return r.tree.HasPath(stereoscopeFile.Path(requestPath))
}

// Stringer to represent a directory path data source
func (r Directory) String() string {
	return fmt.Sprintf("dir:%s", r.path)
}

// FilesByPath returns all file.References that match the given paths from the directory.
func (r Directory) FilesByPath(userPaths ...string) ([]file.Location, error) {
	var references = make([]file.Location, 0)

	for _, userPath := range userPaths {
		userStrPath, err := r.requestPath(userPath)
		if err != nil {
			log.Warnf("unable to get file by path=%q : %+v", userPath, err)
			continue
		}

		// we should be resolving symlinks and preserving this information as a VirtualPath to the real file
		ref, err := r.searchContext.SearchByPath(userStrPath, filetree.FollowBasenameLinks)
		if err != nil {
			log.Tracef("unable to evaluate symlink for path=%q : %+v", userPath, err)
			continue
		}

		if !ref.HasReference() {
			continue
		}

		entry, err := r.index.Get(*ref.Reference)
		if err != nil {
			log.Warnf("unable to get file by path=%q : %+v", userPath, err)
			continue
		}

		// don't consider directories
		if entry.Metadata.IsDir() {
			continue
		}

		if runtime.GOOS == WindowsOS {
			userStrPath = windowsToPosix(userStrPath)
		}

		if ref.HasReference() {
			references = append(references,
				file.NewVirtualLocationFromDirectory(
					r.responsePath(string(ref.RealPath)), // the actual path relative to the resolver root
					r.responsePath(userStrPath),          // the path used to access this file, relative to the resolver root
					*ref.Reference,
				),
			)
		}
	}

	return references, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern from any layer in the image.
func (r Directory) FilesByGlob(patterns ...string) ([]file.Location, error) {
	uniqueFileIDs := stereoscopeFile.NewFileReferenceSet()
	uniqueLocations := make([]file.Location, 0)

	for _, pattern := range patterns {
		refVias, err := r.searchContext.SearchByGlob(pattern, filetree.FollowBasenameLinks)
		if err != nil {
			return nil, err
		}
		for _, refVia := range refVias {
			if !refVia.HasReference() || uniqueFileIDs.Contains(*refVia.Reference) {
				continue
			}
			entry, err := r.index.Get(*refVia.Reference)
			if err != nil {
				return nil, fmt.Errorf("unable to get file metadata for reference %s: %w", refVia.Reference.RealPath, err)
			}

			// don't consider directories
			if entry.Metadata.IsDir() {
				continue
			}

			loc := file.NewVirtualLocationFromDirectory(
				r.responsePath(string(refVia.Reference.RealPath)), // the actual path relative to the resolver root
				r.responsePath(string(refVia.RequestPath)),        // the path used to access this file, relative to the resolver root
				*refVia.Reference,
			)
			uniqueFileIDs.Add(*refVia.Reference)
			uniqueLocations = append(uniqueLocations, loc)
		}
	}

	return uniqueLocations, nil
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another file. For the
// Directory, this is a simple path lookup.
func (r *Directory) RelativeFileByPath(_ file.Location, path string) *file.Location {
	paths, err := r.FilesByPath(path)
	if err != nil {
		return nil
	}
	if len(paths) == 0 {
		return nil
	}

	return &paths[0]
}

// FileContentsByLocation fetches file contents for a single file reference relative to a directory.
// If the path does not exist an error is returned.
func (r Directory) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	if location.RealPath == "" {
		return nil, errors.New("empty path given")
	}

	entry, err := r.index.Get(location.Reference())
	if err != nil {
		return nil, err
	}

	// don't consider directories
	if entry.Type == stereoscopeFile.TypeDirectory {
		return nil, fmt.Errorf("cannot read contents of non-file %q", location.Reference().RealPath)
	}

	// RealPath is posix so for windows directory resolver we need to translate
	// to its true on disk path.
	filePath := string(location.Reference().RealPath)
	if runtime.GOOS == WindowsOS {
		filePath = posixToWindows(filePath)
	}

	return stereoscopeFile.NewLazyReadCloser(filePath), nil
}

func (r *Directory) AllLocations() <-chan file.Location {
	results := make(chan file.Location)
	go func() {
		defer close(results)
		for _, ref := range r.tree.AllFiles(stereoscopeFile.AllTypes()...) {
			results <- file.NewLocationFromDirectory(r.responsePath(string(ref.RealPath)), ref)
		}
	}()
	return results
}

func (r *Directory) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	entry, err := r.index.Get(location.Reference())
	if err != nil {
		return file.Metadata{}, fmt.Errorf("location: %+v : %w", location, os.ErrNotExist)
	}

	return entry.Metadata, nil
}

func (r *Directory) FilesByMIMEType(types ...string) ([]file.Location, error) {
	uniqueFileIDs := stereoscopeFile.NewFileReferenceSet()
	uniqueLocations := make([]file.Location, 0)

	refVias, err := r.searchContext.SearchByMIMEType(types...)
	if err != nil {
		return nil, err
	}
	for _, refVia := range refVias {
		if !refVia.HasReference() {
			continue
		}
		if uniqueFileIDs.Contains(*refVia.Reference) {
			continue
		}
		location := file.NewLocationFromDirectory(
			r.responsePath(string(refVia.Reference.RealPath)),
			*refVia.Reference,
		)
		uniqueFileIDs.Add(*refVia.Reference)
		uniqueLocations = append(uniqueLocations, location)
	}

	return uniqueLocations, nil
}

func windowsToPosix(windowsPath string) (posixPath string) {
	// volume should be encoded at the start (e.g /c/<path>) where c is the volume
	volumeName := filepath.VolumeName(windowsPath)
	pathWithoutVolume := strings.TrimPrefix(windowsPath, volumeName)
	volumeLetter := strings.ToLower(strings.TrimSuffix(volumeName, ":"))

	// translate non-escaped backslash to forwardslash
	translatedPath := strings.ReplaceAll(pathWithoutVolume, "\\", "/")

	// always have `/` as the root... join all components, e.g.:
	// convert: C:\\some\windows\Place
	// into: /c/some/windows/Place
	return path.Clean("/" + strings.Join([]string{volumeLetter, translatedPath}, "/"))
}

func posixToWindows(posixPath string) (windowsPath string) {
	// decode the volume (e.g. /c/<path> --> C:\\) - There should always be a volume name.
	pathFields := strings.Split(posixPath, "/")
	volumeName := strings.ToUpper(pathFields[1]) + `:\\`

	// translate non-escaped forward slashes into backslashes
	remainingTranslatedPath := strings.Join(pathFields[2:], "\\")

	// combine volume name and backslash components
	return filepath.Clean(volumeName + remainingTranslatedPath)
}
