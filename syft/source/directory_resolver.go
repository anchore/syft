package source

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

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

var _ FileResolver = (*directoryResolver)(nil)

type pathFilterFn func(string) bool

// directoryResolver implements path and content access for the directory data source.
type directoryResolver struct {
	path     string
	cwd      string
	fileTree *filetree.FileTree
	infos    map[file.ID]os.FileInfo
	// TODO: wire up to report these paths in the json report
	pathFilterFns []pathFilterFn
	errPaths      map[string]error
}

func newDirectoryResolver(fileTree *filetree.FileTree, root string, pathFilters ...pathFilterFn) (*directoryResolver, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("could not create directory resolver: %w", err)
	}

	var resolverFileTree *filetree.FileTree
	if fileTree == nil {
		resolverFileTree = filetree.NewFileTree()
	} else {
		resolverFileTree = fileTree
	}

	if pathFilters == nil {
		pathFilters = []pathFilterFn{isUnixSystemRuntimePath}
	}

	resolver := directoryResolver{
		path:          root,
		cwd:           cwd,
		fileTree:      resolverFileTree,
		infos:         make(map[file.ID]os.FileInfo),
		pathFilterFns: pathFilters,
		errPaths:      make(map[string]error),
	}

	if fileTree != nil {
		resolver.CopyFromTree()
	}

	return &resolver, indexAllRoots(root, resolver.indexTree)
}

func (r *directoryResolver) CopyFromTree() {
	for _, ref := range r.fileTree.AllFiles() {
		if _, ok := r.infos[ref.ID()]; !ok {
			info, err := os.Stat(string(ref.RealPath))
			if err != nil {
				log.Errorf("unable to copy path=%q: %+v", ref.RealPath, err)
				continue
			}
			r.infos[ref.ID()] = info
		}
	}
}

func (r *directoryResolver) indexTree(root string, stager *progress.Stage) ([]string, error) {
	log.Infof("indexing filesystem path=%q", root)
	var err error
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var roots []string

	return roots, filepath.Walk(root,
		func(path string, info os.FileInfo, err error) error {
			stager.Current = path

			// ignore any path which a filter function returns true
			for _, filterFn := range r.pathFilterFns {
				if filterFn(path) {
					return nil
				}
			}

			if err = r.handleFileAccessErr(path, err); err != nil {
				return err
			}

			// link cycles could cause a revisit --we should not allow this
			if r.fileTree.HasPath(file.Path(path)) {
				return nil
			}

			if info == nil {
				// walk may not be able to provide a FileInfo object, don't allow for this to stop indexing; keep track of the paths and continue.
				r.errPaths[path] = fmt.Errorf("no file info observable at path=%q", path)
				return nil
			}

			newRoot, err := r.addPathToIndex(path, info)
			if err = r.handleFileAccessErr(path, err); err != nil {
				return fmt.Errorf("unable to index path: %w", err)
			}

			if newRoot != "" {
				roots = append(roots, newRoot)
			}

			return nil
		})
}

func (r *directoryResolver) handleFileAccessErr(path string, err error) error {
	if errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist) {
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
	default:
		ref, err = r.fileTree.AddFile(file.Path(p))
		if err != nil {
			return "", err
		}
	}

	r.infos[ref.ID()] = info
	return newRoot, nil
}

func (r directoryResolver) requestPath(userPath string) (string, error) {
	if filepath.IsAbs(userPath) {
		// don't allow input to potentially hop above root path
		userPath = path.Join(r.path, userPath)
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
		return strings.TrimPrefix(path, r.cwd+string(filepath.Separator))
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
		fileMeta, err := os.Stat(userStrPath)
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			log.Warnf("path (%r) is not valid: %+v", userStrPath, err)
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
	return file.NewLazyReadCloser(location.RealPath), nil
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
	info, exists := r.infos[location.ref.ID()]
	if !exists {
		return FileMetadata{}, fmt.Errorf("location: %+v : %w", location, os.ErrNotExist)
	}

	uid := -1
	gid := -1
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid = int(stat.Uid)
		gid = int(stat.Gid)
	}

	return FileMetadata{
		Mode: info.Mode(),
		Type: newFileTypeFromMode(info.Mode()),
		// unsupported across platforms
		UserID:  uid,
		GroupID: gid,
	}, nil
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
