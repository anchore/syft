package source

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
)

const WindowsOS = "windows"

var unixSystemRuntimePrefixes = []string{
	"/proc",
	"/dev",
	"/sys",
}

var errSkipPath = errors.New("skip path")

var _ FileResolver = (*directoryResolver)(nil)

type pathIndexVisitor func(string, os.FileInfo, error) error

// directoryResolver implements path and content access for the directory data source.
type directoryResolver struct {
	path                    string
	base                    string
	currentWdRelativeToRoot string
	currentWd               string
	fileTree                *filetree.FileTree
	fileTreeIndex           filetree.Index
	searchContext           filetree.Searcher
	metadata                map[file.ID]FileMetadata
	// TODO: wire up to report these paths in the json report
	pathIndexVisitors []pathIndexVisitor
	errPaths          map[string]error
}

func newDirectoryResolver(root string, base string, pathFilters ...pathIndexVisitor) (*directoryResolver, error) {
	resolver, err := newDirectoryResolverWithoutIndex(root, base, pathFilters...)
	if err != nil {
		return nil, err
	}

	return resolver, resolver.index()
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

	resolver := &directoryResolver{
		path:                    cleanRoot,
		base:                    cleanBase,
		currentWd:               cleanCWD,
		currentWdRelativeToRoot: currentWdRelRoot,
		fileTree:                filetree.NewFileTree(),
		fileTreeIndex:           filetree.NewIndex(),
		metadata:                make(map[file.ID]FileMetadata),
		pathIndexVisitors:       append([]pathIndexVisitor{requireFileInfo, disallowByFileType, disallowUnixSystemRuntimePath}, pathFilters...),
		errPaths:                make(map[string]error),
	}

	// these additional stateful visitors should be the first thing considered when walking / indexing
	resolver.pathIndexVisitors = append([]pathIndexVisitor{resolver.disallowRevisitingVisitor, resolver.disallowFileAccessErr}, resolver.pathIndexVisitors...)

	return resolver, nil
}

func (r *directoryResolver) index() error {
	return indexAllRoots(r.path, r.indexTree)
}

func (r *directoryResolver) disallowRevisitingVisitor(path string, _ os.FileInfo, _ error) error {
	// this prevents visiting:
	// - link destinations twice, once for the real file and another through the virtual path
	// - infinite link cycles
	if indexed, metadata := r.hasBeenIndexed(path); indexed {
		if metadata.IsDir {
			// signal to walk() that we should skip this directory entirely
			return fs.SkipDir
		}
		return errSkipPath
	}
	return nil
}

func requireFileInfo(_ string, info os.FileInfo, _ error) error {
	if info == nil {
		return errSkipPath
	}
	return nil
}

func (r *directoryResolver) indexTree(root string, stager *progress.Stage) ([]string, error) {
	log.WithFields("path", root).Trace("indexing filetree")

	var roots []string
	var err error

	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	// we want to be able to index single files with the directory resolver. However, we should also allow for attempting
	// to index paths that do not exist (that is, a root that does not exist is not an error case that should stop indexing).
	// For this reason we look for an opportunity to discover if the given root is a file, and if so add a single root,
	// but continue forth with index regardless if the given root path exists or not.
	fi, err := os.Stat(root)
	if err != nil && fi != nil && !fi.IsDir() {
		// note: we want to index the path regardless of an error stat-ing the path
		newRoot, _ := r.indexPath(root, fi, nil)
		if newRoot != "" {
			roots = append(roots, newRoot)
		}
		return roots, nil
	}

	err = filepath.Walk(root,
		func(path string, info os.FileInfo, err error) error {
			stager.Current = path

			newRoot, err := r.indexPath(path, info, err)

			if err != nil {
				return err
			}

			if newRoot != "" {
				roots = append(roots, newRoot)
			}

			return nil
		})

	if err != nil {
		return nil, fmt.Errorf("unable to index root=%q: %w", root, err)
	}

	r.searchContext = filetree.NewSearchContext(r.fileTree, r.fileTreeIndex)

	return roots, nil
}

func (r *directoryResolver) indexPath(path string, info os.FileInfo, err error) (string, error) {
	// ignore any path which a filter function returns true
	for _, filterFn := range r.pathIndexVisitors {
		if filterFn == nil {
			continue
		}

		if filterErr := filterFn(path, info, err); filterErr != nil {
			if errors.Is(filterErr, fs.SkipDir) {
				// signal to walk() to skip this directory entirely (even if we're processing a file)
				return "", filterErr
			}
			// skip this path but don't affect walk() trajectory
			return "", nil
		}
	}

	if info == nil {
		// walk may not be able to provide a FileInfo object, don't allow for this to stop indexing; keep track of the paths and continue.
		r.errPaths[path] = fmt.Errorf("no file info observable at path=%q", path)
		return "", nil
	}

	// here we check to see if we need to normalize paths to posix on the way in coming from windows
	if runtime.GOOS == WindowsOS {
		path = windowsToPosix(path)
	}

	newRoot, err := r.addPathToIndex(path, info)
	if r.isFileAccessErr(path, err) {
		return "", nil
	}

	return newRoot, nil
}

func (r *directoryResolver) disallowFileAccessErr(path string, _ os.FileInfo, err error) error {
	if r.isFileAccessErr(path, err) {
		return errSkipPath
	}
	return nil
}

func (r *directoryResolver) isFileAccessErr(path string, err error) bool {
	// don't allow for errors to stop indexing, keep track of the paths and continue.
	if err != nil {
		log.Warnf("unable to access path=%q: %+v", path, err)
		r.errPaths[path] = err
		return true
	}
	return false
}

func (r directoryResolver) addPathToIndex(p string, info os.FileInfo) (string, error) {
	switch t := file.TypeFromMode(info.Mode()); t {
	case file.TypeSymlink:
		return r.addSymlinkToIndex(p, info)
	case file.TypeDir:
		return "", r.addDirectoryToIndex(p, info)
	case file.TypeReg:
		return "", r.addFileToIndex(p, info)
	default:
		return "", fmt.Errorf("unsupported file type: %s", t)
	}
}

func (r directoryResolver) hasBeenIndexed(p string) (bool, *file.Metadata) {
	filePath := file.Path(p)
	if !r.fileTree.HasPath(filePath) {
		return false, nil
	}

	exists, ref, err := r.fileTree.File(filePath)
	if err != nil || !exists || !ref.HasReference() {
		return false, nil
	}

	// cases like "/" will be in the tree, but not been indexed yet (a special case). We want to capture
	// these cases as new paths to index.
	if !ref.HasReference() {
		return false, nil
	}

	entry, err := r.fileTreeIndex.Get(*ref.Reference)
	if err != nil {
		return false, nil
	}

	return true, &entry.Metadata
}

func (r directoryResolver) addDirectoryToIndex(p string, info os.FileInfo) error {
	ref, err := r.fileTree.AddDir(file.Path(p))
	if err != nil {
		return err
	}

	metadata := file.NewMetadataFromPath(p, info)
	r.addFileToFileTreeIndex(ref, metadata)
	r.fileTreeIndex.Add(*ref, metadata)

	return nil
}

func (r directoryResolver) addFileToIndex(p string, info os.FileInfo) error {
	ref, err := r.fileTree.AddFile(file.Path(p))
	if err != nil {
		return err
	}

	metadata := file.NewMetadataFromPath(p, info)
	r.addFileToFileTreeIndex(ref, metadata)
	r.fileTreeIndex.Add(*ref, metadata)

	return nil
}

func (r directoryResolver) addSymlinkToIndex(p string, info os.FileInfo) (string, error) {
	linkTarget, err := os.Readlink(p)
	if err != nil {
		return "", fmt.Errorf("unable to readlink for path=%q: %w", p, err)
	}

	if filepath.IsAbs(linkTarget) {
		// if the link is absolute (e.g, /bin/ls -> /bin/busybox) we need to
		// resolve relative to the root of the base directory
		linkTarget = filepath.Join(r.base, filepath.Clean(linkTarget))
	} else {
		// if the link is not absolute (e.g, /dev/stderr -> fd/2 ) we need to
		// resolve it relative to the directory in question (e.g. resolve to
		// /dev/fd/2)
		if r.base == "" {
			linkTarget = filepath.Join(filepath.Dir(p), linkTarget)
		} else {
			// if the base is set, then we first need to resolve the link,
			// before finding it's location in the base
			dir, err := filepath.Rel(r.base, filepath.Dir(p))
			if err != nil {
				return "", fmt.Errorf("unable to resolve relative path for path=%q: %w", p, err)
			}
			linkTarget = filepath.Join(r.base, filepath.Clean(filepath.Join("/", dir, linkTarget)))
		}
	}

	ref, err := r.fileTree.AddSymLink(file.Path(p), file.Path(linkTarget))
	if err != nil {
		return "", err
	}

	targetAbsPath := linkTarget
	if !filepath.IsAbs(targetAbsPath) {
		targetAbsPath = filepath.Clean(filepath.Join(path.Dir(p), linkTarget))
	}

	metadata := file.NewMetadataFromPath(p, info)
	metadata.LinkDestination = linkTarget
	r.addFileToFileTreeIndex(ref, metadata)
	r.fileTreeIndex.Add(*ref, metadata)

	return targetAbsPath, nil
}

func (r directoryResolver) addFileToFileTreeIndex(ref *file.Reference, metadata FileMetadata) {
	if ref != nil {
		r.metadata[ref.ID()] = metadata
	}
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

	// always return references relative to the request path (not absolute path)
	if filepath.IsAbs(path) {
		// we need to account for the cwd relative to the running process and the given root for the directory resolver
		prefix := filepath.Clean(filepath.Join(r.currentWd, r.currentWdRelativeToRoot))
		return strings.TrimPrefix(path, prefix+string(filepath.Separator))
	}
	return path
}

// HasPath indicates if the given path exists in the underlying source.
func (r *directoryResolver) HasPath(userPath string) bool {
	requestPath, err := r.requestPath(userPath)
	if err != nil {
		return false
	}
	return r.fileTree.HasPath(file.Path(requestPath))
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

		entry, err := r.fileTreeIndex.Get(*ref.Reference)
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
			entry, err := r.fileTreeIndex.Get(*refVia.Reference)
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

	entry, err := r.fileTreeIndex.Get(location.ref)
	if err != nil {
		return nil, err
	}

	// don't consider directories
	if entry.Type == file.TypeDir {
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
		for _, ref := range r.fileTree.AllFiles(file.AllTypes()...) {
			results <- NewLocationFromDirectory(r.responsePath(string(ref.RealPath)), ref)
		}
	}()
	return results
}

func (r *directoryResolver) FileMetadataByLocation(location Location) (FileMetadata, error) {
	metadata, exists := r.metadata[location.ref.ID()]
	if !exists {
		return FileMetadata{}, fmt.Errorf("location: %+v : %w", location, os.ErrNotExist)
	}

	return metadata, nil
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

func disallowUnixSystemRuntimePath(path string, _ os.FileInfo, _ error) error {
	if internal.HasAnyOfPrefixes(path, unixSystemRuntimePrefixes...) {
		return fs.SkipDir
	}
	return nil
}

func disallowByFileType(_ string, info os.FileInfo, _ error) error {
	if info == nil {
		// we can't filter out by filetype for non-existent files
		return nil
	}
	switch file.TypeFromMode(info.Mode()) {
	case file.TypeCharacterDevice, file.TypeSocket, file.TypeBlockDevice, file.TypeFifo, file.TypeIrregular:
		return errSkipPath
		// note: symlinks that point to these files may still get by.
		// We handle this later in processing to help prevent against infinite links traversal.
	}

	return nil
}

func indexAllRoots(root string, indexer func(string, *progress.Stage) ([]string, error)) error {
	// why account for multiple roots? To cover cases when there is a symlink that references above the root path,
	// in which case we need to additionally index where the link resolves to. it's for this reason why the filetree
	// must be relative to the root of the filesystem (and not just relative to the given path).
	pathsToIndex := []string{root}
	fullPathsMap := map[string]struct{}{}

	stager, prog := indexingProgress(root)
	defer prog.SetCompleted()
loop:
	for {
		var currentPath string
		switch len(pathsToIndex) {
		case 0:
			break loop
		case 1:
			currentPath, pathsToIndex = pathsToIndex[0], nil
		default:
			currentPath, pathsToIndex = pathsToIndex[0], pathsToIndex[1:]
		}

		additionalRoots, err := indexer(currentPath, stager)
		if err != nil {
			return fmt.Errorf("unable to index filesystem path=%q: %w", currentPath, err)
		}

		for _, newRoot := range additionalRoots {
			if _, ok := fullPathsMap[newRoot]; !ok {
				fullPathsMap[newRoot] = struct{}{}
				pathsToIndex = append(pathsToIndex, newRoot)
			}
		}
	}

	return nil
}

func indexingProgress(path string) (*progress.Stage, *progress.Manual) {
	stage := &progress.Stage{}
	prog := &progress.Manual{
		Total: -1,
	}

	bus.Publish(partybus.Event{
		Type:   event.FileIndexingStarted,
		Source: path,
		Value: struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       progress.Stager(stage),
			Progressable: prog,
		},
	})

	return stage, prog
}
