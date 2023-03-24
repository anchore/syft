package source

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/internal/log"
)

const WindowsOS = "windows"

var unixSystemRuntimePrefixes = []string{
	"/proc",
	"/dev",
	"/sys",
}

var errSkipPath = errors.New("skip path")

var _ FileResolver = (*directoryResolver)(nil)

// directoryResolver implements path and content access for the directory data source.
type directoryResolver struct {
	path                    string
	base                    string
	currentWdRelativeToRoot string
	currentWd               string
	tree                    filetree.Reader
	index                   filetree.IndexReader
	searchContext           filetree.Searcher
	indexer                 *directoryIndexer
}

func newDirectoryResolver(root string, base string, pathFilters ...pathIndexVisitor) (*directoryResolver, error) {
	r, err := newDirectoryResolverWithoutIndex(root, base, pathFilters...)
	if err != nil {
		return nil, err
	}

	return r, r.buildIndex()
}

func newDirectoryResolverWithoutIndex(root string, base string, pathFilters ...pathIndexVisitor) (*directoryResolver, error) {
	currentWD, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("could not get CWD: %w", err)
	}
	// we have to account for the root being accessed through a symlink path and always resolve the real path. Otherwise
	// we will not be able to normalize given paths that fall under the resolver
	cleanCWD, err := filepath.EvalSymlinks(currentWD)
	if err != nil {
		return nil, fmt.Errorf("could not evaluate CWD symlinks: %w", err)
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
		currentWdRelRoot, err = filepath.Rel(cleanCWD, cleanRoot)
		if err != nil {
			return nil, fmt.Errorf("could not determine given root path to CWD: %w", err)
		}
	} else {
		currentWdRelRoot = filepath.Clean(cleanRoot)
	}

	return &directoryResolver{
		path:                    cleanRoot,
		base:                    cleanBase,
		currentWd:               cleanCWD,
		currentWdRelativeToRoot: currentWdRelRoot,
		tree:                    filetree.New(),
		index:                   filetree.NewIndex(),
		indexer:                 newDirectoryIndexer(cleanRoot, cleanBase, pathFilters...),
	}, nil
}

func (r *directoryResolver) buildIndex() error {
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

func (r directoryResolver) requestPath(userPath string) (string, error) {
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

func (r directoryResolver) responsePath(path string) string {
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
func (r *directoryResolver) HasPath(userPath string) bool {
	requestPath, err := r.requestPath(userPath)
	if err != nil {
		return false
	}
	return r.tree.HasPath(file.Path(requestPath))
}

// Stringer to represent a directory path data source
func (r directoryResolver) String() string {
	return fmt.Sprintf("dir:%s", r.path)
}

// FilesByPath returns all file.References that match the given paths from the directory.
func (r directoryResolver) FilesByPath(userPaths ...string) ([]Location, error) {
	var references = make([]Location, 0)

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
		if entry.Metadata.IsDir {
			continue
		}

		if runtime.GOOS == WindowsOS {
			userStrPath = windowsToPosix(userStrPath)
		}

		if ref.HasReference() {
			references = append(references,
				NewVirtualLocationFromDirectory(
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
func (r directoryResolver) FilesByGlob(patterns ...string) ([]Location, error) {
	uniqueFileIDs := file.NewFileReferenceSet()
	uniqueLocations := make([]Location, 0)

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
			if entry.Metadata.IsDir {
				continue
			}

			loc := NewVirtualLocationFromDirectory(
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
// directoryResolver, this is a simple path lookup.
func (r *directoryResolver) RelativeFileByPath(_ Location, path string) *Location {
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
func (r directoryResolver) FileContentsByLocation(location Location) (io.ReadCloser, error) {
	if location.ref.RealPath == "" {
		return nil, errors.New("empty path given")
	}

	entry, err := r.index.Get(location.ref)
	if err != nil {
		return nil, err
	}

	// don't consider directories
	if entry.Type == file.TypeDirectory {
		return nil, fmt.Errorf("cannot read contents of non-file %q", location.ref.RealPath)
	}

	// RealPath is posix so for windows directory resolver we need to translate
	// to its true on disk path.
	filePath := string(location.ref.RealPath)
	if runtime.GOOS == WindowsOS {
		filePath = posixToWindows(filePath)
	}

	return file.NewLazyReadCloser(filePath), nil
}

func (r *directoryResolver) AllLocations() <-chan Location {
	results := make(chan Location)
	go func() {
		defer close(results)
		for _, ref := range r.tree.AllFiles(file.AllTypes()...) {
			results <- NewLocationFromDirectory(r.responsePath(string(ref.RealPath)), ref)
		}
	}()
	return results
}

func (r *directoryResolver) FileMetadataByLocation(location Location) (FileMetadata, error) {
	entry, err := r.index.Get(location.ref)
	if err != nil {
		return FileMetadata{}, fmt.Errorf("location: %+v : %w", location, os.ErrNotExist)
	}

	return entry.Metadata, nil
}

func (r *directoryResolver) FilesByMIMEType(types ...string) ([]Location, error) {
	uniqueFileIDs := file.NewFileReferenceSet()
	uniqueLocations := make([]Location, 0)

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
		location := NewLocationFromDirectory(
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
