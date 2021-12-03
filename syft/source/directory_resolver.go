package source

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
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

var unixSystemRuntimePrefixes = []string{
	"/proc",
	"/sys",
	"/dev",
}

var ErrIgnoreIrregularFile = errors.New("ignoring irregular file type")

var _ FileResolver = (*directoryResolver)(nil)

type pathFilterFn func(string) bool

// directoryResolver implements path and content access for the directory data source.
type directoryResolver struct {
	path              string
	cwdRelativeToRoot string
	cwd               string
	fileTree          *filetree.FileTree
	metadata          map[file.ID]FileMetadata
	// TODO: wire up to report these paths in the json report
	pathFilterFns  []pathFilterFn
	refsByMIMEType map[string][]file.Reference
	errPaths       map[string]error
}

func newDirectoryResolver(root string, pathFilters ...pathFilterFn) (*directoryResolver, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("could not create directory resolver: %w", err)
	}

	var cwdRelRoot string
	if path.IsAbs(root) {
		cwdRelRoot, err = filepath.Rel(cwd, root)
		if err != nil {
			return nil, fmt.Errorf("could not create directory resolver: %w", err)
		}
	}

	if pathFilters == nil {
		pathFilters = []pathFilterFn{isUnixSystemRuntimePath}
	}

	resolver := directoryResolver{
		path:              root,
		cwd:               cwd,
		cwdRelativeToRoot: cwdRelRoot,
		fileTree:          filetree.NewFileTree(),
		metadata:          make(map[file.ID]FileMetadata),
		pathFilterFns:     pathFilters,
		refsByMIMEType:    make(map[string][]file.Reference),
		errPaths:          make(map[string]error),
	}

	return &resolver, indexAllRoots(root, resolver.indexTree)
}

func (r *directoryResolver) indexTree(root string, stager *progress.Stage) ([]string, error) {
	log.Infof("indexing filesystem path=%q", root)

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
		newRoot, err := r.addPathToIndex(root, fi)
		if err = r.handleFileAccessErr(root, err); err != nil {
			return nil, fmt.Errorf("unable to index path: %w", err)
		}

		if newRoot != "" {
			roots = append(roots, newRoot)
		}
		return roots, nil
	}

	return roots, filepath.Walk(root,
		func(path string, info os.FileInfo, err error) error {
			stager.Current = path

			newRoot, indexErr := r.indexPath(path, info, err)
			if newRoot != "" {
				roots = append(roots, newRoot)
			}

			return indexErr
		})
}

func (r *directoryResolver) indexPath(path string, info os.FileInfo, err error) (string, error) {
	// ignore any path which a filter function returns true
	for _, filterFn := range r.pathFilterFns {
		if filterFn(path) {
			return "", nil
		}
	}

	if err = r.handleFileAccessErr(path, err); err != nil {
		return "", err
	}

	// link cycles could cause a revisit --we should not allow this
	if r.fileTree.HasPath(file.Path(path)) {
		return "", nil
	}

	if info == nil {
		// walk may not be able to provide a FileInfo object, don't allow for this to stop indexing; keep track of the paths and continue.
		r.errPaths[path] = fmt.Errorf("no file info observable at path=%q", path)
		return "", nil
	}

	newRoot, err := r.addPathToIndex(path, info)
	if err = r.handleFileAccessErr(path, err); err != nil {
		return "", fmt.Errorf("unable to index path: %w", err)
	}

	return newRoot, nil
}

func (r *directoryResolver) handleFileAccessErr(path string, err error) error {
	if errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrIgnoreIrregularFile) {
		// don't allow for permission errors to stop indexing, keep track of the paths and continue.
		log.Warnf("unable to access path=%q: %+v", path, err)
		r.errPaths[path] = err
		return nil
	} else if err != nil {
		return fmt.Errorf("unable to access path=%q: %w", path, err)
	}
	return nil
}

func (r directoryResolver) addPathToIndex(p string, info os.FileInfo) (string, error) {
	var ref *file.Reference
	var err error
	var newRoot string

	switch newFileTypeFromMode(info.Mode()) {
	case SymbolicLink:
		linkTarget, err := os.Readlink(p)
		if err != nil {
			return "", fmt.Errorf("unable to readlink for path=%q: %w", p, err)
		}
		ref, err = r.fileTree.AddSymLink(file.Path(p), file.Path(linkTarget))
		if err != nil {
			return "", err
		}

		targetAbsPath := linkTarget
		if !filepath.IsAbs(targetAbsPath) {
			targetAbsPath = filepath.Clean(filepath.Join(path.Dir(p), linkTarget))
		}

		newRoot = targetAbsPath

	case Directory:
		ref, err = r.fileTree.AddDir(file.Path(p))
		if err != nil {
			return "", err
		}
	case IrregularFile:
		return "", ErrIgnoreIrregularFile
	default:
		ref, err = r.fileTree.AddFile(file.Path(p))
		if err != nil {
			return "", err
		}
	}

	metadata := fileMetadataFromPath(p, info)
	if ref != nil {
		r.refsByMIMEType[metadata.MIMEType] = append(r.refsByMIMEType[metadata.MIMEType], *ref)
	}

	r.metadata[ref.ID()] = metadata
	return newRoot, nil
}

func (r directoryResolver) requestPath(userPath string) (string, error) {
	if filepath.IsAbs(userPath) {
		// don't allow input to potentially hop above root path
		userPath = path.Join(r.path, userPath)
	} else {
		// ensure we take into account any relative difference between the root path and the CWD for relative requests
		userPath = path.Join(r.cwdRelativeToRoot, userPath)
	}

	var err error
	userPath, err = filepath.Abs(userPath)
	if err != nil {
		return "", err
	}
	return userPath, nil
}

func (r directoryResolver) responsePath(path string) string {
	// always return references relative to the request path (not absolute path)
	if filepath.IsAbs(path) {
		// we need to account for the cwd relative to the running process and the given root for the directory resolver
		prefix := filepath.Clean(filepath.Join(r.cwd, r.cwdRelativeToRoot))
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

		// TODO: why not use stored metadata?
		fileMeta, err := os.Stat(userStrPath)
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
				log.Warnf("path is not valid (%s): %+v", userStrPath, err)
			}
			continue
		}

		// don't consider directories
		if fileMeta.IsDir() {
			continue
		}

		exists, ref, err := r.fileTree.File(file.Path(userStrPath))
		if err == nil && exists {
			references = append(references, NewLocationFromDirectory(r.responsePath(userStrPath), *ref))
		} else {
			log.Warnf("path (%s) not found in file tree: Exists: %t Err:%+v", userStrPath, exists, err)
		}
	}

	return references, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern from any layer in the image.
func (r directoryResolver) FilesByGlob(patterns ...string) ([]Location, error) {
	result := make([]Location, 0)

	for _, pattern := range patterns {
		globResults, err := r.fileTree.FilesByGlob(pattern)
		if err != nil {
			return nil, err
		}
		for _, globResult := range globResults {
			result = append(result, NewLocationFromDirectory(r.responsePath(string(globResult.MatchPath)), globResult.Reference))
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
	return file.NewLazyReadCloser(string(location.ref.RealPath)), nil
}

func (r *directoryResolver) AllLocations() <-chan Location {
	results := make(chan Location)
	go func() {
		defer close(results)
		for _, ref := range r.fileTree.AllFiles() {
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

func isUnixSystemRuntimePath(path string) bool {
	return internal.HasAnyOfPrefixes(path, unixSystemRuntimePrefixes...)
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
