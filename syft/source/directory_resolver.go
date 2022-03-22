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

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

const WindowsOS = "windows"

var unixSystemRuntimePrefixes = []string{
	"/proc",
	"/dev",
	"/sys",
}

var _ FileResolver = (*directoryResolver)(nil)

type pathFilterFn func(string, os.FileInfo) bool

// directoryResolver implements path and content access for the directory data source.
type directoryResolver struct {
	path                    string
	currentWdRelativeToRoot string
	currentWd               string
	fileTree                *filetree.FileTree
	metadata                map[file.ID]FileMetadata
	// TODO: wire up to report these paths in the json report
	pathFilterFns  []pathFilterFn
	refsByMIMEType map[string][]file.Reference
	errPaths       map[string]error
}

func newDirectoryResolver(root string, pathFilters ...pathFilterFn) (*directoryResolver, error) {
	currentWD, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("could not gret CWD: %w", err)
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

	var currentWdRelRoot string
	if path.IsAbs(cleanRoot) {
		currentWdRelRoot, err = filepath.Rel(cleanCWD, cleanRoot)
		if err != nil {
			return nil, fmt.Errorf("could not determine given root path to CWD: %w", err)
		}
	} else {
		currentWdRelRoot = filepath.Clean(cleanRoot)
	}

	resolver := directoryResolver{
		path:                    cleanRoot,
		currentWd:               cleanCWD,
		currentWdRelativeToRoot: currentWdRelRoot,
		fileTree:                filetree.NewFileTree(),
		metadata:                make(map[file.ID]FileMetadata),
		pathFilterFns:           append([]pathFilterFn{isUnallowableFileType, isUnixSystemRuntimePath}, pathFilters...),
		refsByMIMEType:          make(map[string][]file.Reference),
		errPaths:                make(map[string]error),
	}

	return &resolver, indexAllRoots(cleanRoot, resolver.indexTree)
}

func (r *directoryResolver) indexTree(root string, stager *progress.Stage) ([]string, error) {
	log.Debugf("indexing filesystem path=%q", root)

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

	return roots, filepath.Walk(root,
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
}

func (r *directoryResolver) indexPath(path string, info os.FileInfo, err error) (string, error) {
	// ignore any path which a filter function returns true
	for _, filterFn := range r.pathFilterFns {
		if filterFn != nil && filterFn(path, info) {
			if info.IsDir() {
				return "", fs.SkipDir
			}
			return "", nil
		}
	}

	if r.isFileAccessErr(path, err) {
		return "", nil
	}

	// link cycles could cause a revisit --we should not allow this
	if r.hasBeenIndexed(path) {
		return "", nil
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
	switch t := newFileTypeFromMode(info.Mode()); t {
	case SymbolicLink:
		return r.addSymlinkToIndex(p, info)
	case Directory:
		return "", r.addDirectoryToIndex(p, info)
	case RegularFile:
		return "", r.addFileToIndex(p, info)
	default:
		return "", fmt.Errorf("unsupported file type: %s", t)
	}
}

func (r directoryResolver) hasBeenIndexed(p string) bool {
	filePath := file.Path(p)
	if !r.fileTree.HasPath(filePath) {
		return false
	}

	exists, ref, err := r.fileTree.File(filePath)
	if err != nil || !exists || ref == nil {
		return false
	}

	// cases like "/" will be in the tree, but not been indexed yet (a special case). We want to capture
	// these cases as new paths to index.
	_, exists = r.metadata[ref.ID()]
	return exists
}

func (r directoryResolver) addDirectoryToIndex(p string, info os.FileInfo) error {
	ref, err := r.fileTree.AddDir(file.Path(p))
	if err != nil {
		return err
	}

	location := NewLocationFromDirectory(p, *ref)
	metadata := fileMetadataFromPath(p, info, r.isInIndex(location))
	r.addFileMetadataToIndex(ref, metadata)

	return nil
}

func (r directoryResolver) addFileToIndex(p string, info os.FileInfo) error {
	ref, err := r.fileTree.AddFile(file.Path(p))
	if err != nil {
		return err
	}

	location := NewLocationFromDirectory(p, *ref)
	metadata := fileMetadataFromPath(p, info, r.isInIndex(location))
	r.addFileMetadataToIndex(ref, metadata)

	return nil
}

func (r directoryResolver) addSymlinkToIndex(p string, info os.FileInfo) (string, error) {
	var usedInfo = info

	linkTarget, err := os.Readlink(p)
	if err != nil {
		return "", fmt.Errorf("unable to readlink for path=%q: %w", p, err)
	}

	// note: if the link is not absolute (e.g, /dev/stderr -> fd/2 ) we need to resolve it relative to the directory
	// in question (e.g. resolve to /dev/fd/2)
	if !filepath.IsAbs(linkTarget) {
		linkTarget = filepath.Join(filepath.Dir(p), linkTarget)
	}

	ref, err := r.fileTree.AddSymLink(file.Path(p), file.Path(linkTarget))
	if err != nil {
		return "", err
	}

	targetAbsPath := linkTarget
	if !filepath.IsAbs(targetAbsPath) {
		targetAbsPath = filepath.Clean(filepath.Join(path.Dir(p), linkTarget))
	}

	location := NewLocationFromDirectory(p, *ref)
	location.VirtualPath = p
	metadata := fileMetadataFromPath(p, usedInfo, r.isInIndex(location))
	metadata.LinkDestination = linkTarget
	r.addFileMetadataToIndex(ref, metadata)

	return targetAbsPath, nil
}

func (r directoryResolver) addFileMetadataToIndex(ref *file.Reference, metadata FileMetadata) {
	if ref != nil {
		if metadata.MIMEType != "" {
			r.refsByMIMEType[metadata.MIMEType] = append(r.refsByMIMEType[metadata.MIMEType], *ref)
		}
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
		evaluatedPath, err := filepath.EvalSymlinks(userStrPath)
		if err != nil {
			log.Warnf("directory resolver unable to evaluate symlink for path=%q : %+v", userPath, err)
			continue
		}

		// TODO: why not use stored metadata?
		fileMeta, err := os.Stat(evaluatedPath)
		if errors.Is(err, os.ErrNotExist) {
			// note: there are other kinds of errors other than os.ErrNotExist that may be given that is platform
			// specific, but essentially hints at the same overall problem (that the path does not exist). Such an
			// error could be syscall.ENOTDIR (see https://github.com/golang/go/issues/18974).
			continue
		} else if err != nil {
			// we don't want to consider any other syscalls that may hint at non-existence of the file/dir as
			// invalid paths. This logging statement is meant to raise IO or permissions related problems.
			var pathErr *os.PathError
			if !errors.As(err, &pathErr) {
				log.Warnf("path is not valid (%s): %+v", evaluatedPath, err)
			}
			continue
		}

		// don't consider directories
		if fileMeta.IsDir() {
			continue
		}

		if runtime.GOOS == WindowsOS {
			userStrPath = windowsToPosix(userStrPath)
		}

		exists, ref, err := r.fileTree.File(file.Path(userStrPath), filetree.FollowBasenameLinks)
		if err == nil && exists {
			loc := NewVirtualLocationFromDirectory(
				r.responsePath(string(ref.RealPath)), // the actual path relative to the resolver root
				r.responsePath(userStrPath),          // the path used to access this file, relative to the resolver root
				*ref,
			)
			references = append(references, loc)
		}
	}

	return references, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern from any layer in the image.
func (r directoryResolver) FilesByGlob(patterns ...string) ([]Location, error) {
	result := make([]Location, 0)

	for _, pattern := range patterns {
		globResults, err := r.fileTree.FilesByGlob(pattern, filetree.FollowBasenameLinks)
		if err != nil {
			return nil, err
		}
		for _, globResult := range globResults {
			loc := NewVirtualLocationFromDirectory(
				r.responsePath(string(globResult.Reference.RealPath)), // the actual path relative to the resolver root
				r.responsePath(string(globResult.MatchPath)),          // the path used to access this file, relative to the resolver root
				globResult.Reference,
			)
			result = append(result, loc)
		}
	}

	return result, nil
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
	if !r.isInIndex(location) {
		// this is in cases where paths have been explicitly excluded from the tree index. In which case
		// we should DENY all content requests. Why? These paths have been indicated to be inaccessible (either
		// by preference or these files are not readable by the current user).
		return nil, fmt.Errorf("file content is inaccessible path=%q", location.ref.RealPath)
	}
	// RealPath is posix so for windows directory resolver we need to translate
	// to its true on disk path.
	filePath := string(location.ref.RealPath)
	if runtime.GOOS == WindowsOS {
		filePath = posixToWindows(filePath)
	}
	return file.NewLazyReadCloser(filePath), nil
}

func (r directoryResolver) isInIndex(location Location) bool {
	if location.ref.RealPath == "" {
		return false
	}
	return r.fileTree.HasPath(location.ref.RealPath, filetree.FollowBasenameLinks)
}

func (r *directoryResolver) AllLocations() <-chan Location {
	results := make(chan Location)
	go func() {
		defer close(results)
		// this should be all non-directory types
		for _, ref := range r.fileTree.AllFiles(file.TypeReg, file.TypeSymlink, file.TypeHardLink, file.TypeBlockDevice, file.TypeCharacterDevice, file.TypeFifo) {
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
	var locations []Location
	for _, ty := range types {
		if refs, ok := r.refsByMIMEType[ty]; ok {
			for _, ref := range refs {
				locations = append(locations, NewLocationFromDirectory(r.responsePath(string(ref.RealPath)), ref))
			}
		}
	}
	return locations, nil
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

func isUnixSystemRuntimePath(path string, _ os.FileInfo) bool {
	return internal.HasAnyOfPrefixes(path, unixSystemRuntimePrefixes...)
}

func isUnallowableFileType(_ string, info os.FileInfo) bool {
	if info == nil {
		// we can't filter out by filetype for non-existent files
		return false
	}
	switch newFileTypeFromMode(info.Mode()) {
	case CharacterDevice, Socket, BlockDevice, FIFONode, IrregularFile:
		return true
		// note: symlinks that point to these files may still get by.
		// We handle this later in processing to help prevent against infinite links traversal.
	}

	return false
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
