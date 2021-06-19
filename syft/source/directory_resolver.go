package source

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/syft/event"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
)

var systemRuntimePrefixes = []string{
	"/proc",
	"/sys",
	"/dev",
}

var _ FileResolver = (*directoryResolver)(nil)

// directoryResolver implements path and content access for the directory data source.
type directoryResolver struct {
	path     string
	cwd      string
	fileTree *filetree.FileTree
	infos    map[file.ID]os.FileInfo
	// TODO: wire up to report these paths in the json report
	errPaths map[string]error
}

func newDirectoryResolver(root string) (*directoryResolver, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("could not create directory resolver: %w", err)
	}

	r := directoryResolver{
		path:     root,
		cwd:      cwd,
		fileTree: filetree.NewFileTree(),
		infos:    make(map[file.ID]os.FileInfo),
		errPaths: make(map[string]error),
	}

	// why account for multiple roots? To cover cases when there is a symlink that references above the root path,
	// in which case we need to additionally index where the link resolves to.
	// it's for this reason why the filetree must be relative to root.
	roots := []string{root}
	for _, p := range roots {
		additionalRoots, err := r.indexPath(p)
		if err != nil {
			return nil, fmt.Errorf("unable to index filesystem: %w", err)
		}
		roots = append(roots, additionalRoots...)
	}

	return &r, nil
}

func (r *directoryResolver) indexPath(root string) ([]string, error) {
	log.Infof("indexing filesystem path=%q", root)
	var err error
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var roots []string
	stager, prog := indexingProgress(root)
	defer prog.SetCompleted()

	return roots, filepath.Walk(root,
		func(p string, info os.FileInfo, err error) error {
			stager.Current = p

			if isSystemRuntimePath(p) {
				return nil
			}

			// permission denied, IO error, etc... we keep track of the paths we can't see, but continue with indexing
			if err != nil {
				log.Warnf("unable to index path=%q: %+v", p, err)
				r.errPaths[p] = err
				return nil
			}

			// link cycles could cause a revisit --we should not allow this
			if r.fileTree.HasPath(file.Path(p)) {
				return nil
			}

			var ref *file.Reference
			switch newFileTypeFromMode(info.Mode()) {
			case SymbolicLink:
				linkTarget, err := os.Readlink(p)
				if err != nil {
					if errors.Is(err, os.ErrPermission) {
						// don't allow for permission errors to stop indexing, keep track of the paths and continue.
						log.Warnf("unable to index symlink=%q: %+v", p, err)
						r.errPaths[p] = err
						return nil
					}
					return fmt.Errorf("unable to readlink for path=%q: %+v", p, err)
				}
				ref, err = r.fileTree.AddSymLink(file.Path(p), file.Path(linkTarget))
				if err != nil {
					return err
				}

				targetAbsPath := linkTarget
				if !filepath.IsAbs(targetAbsPath) {
					targetAbsPath = filepath.Clean(filepath.Join(path.Dir(p), linkTarget))
				}

				roots = append(roots, targetAbsPath)

			case Directory:
				ref, err = r.fileTree.AddDir(file.Path(p))
				if err != nil {
					return err
				}
			default:
				ref, err = r.fileTree.AddFile(file.Path(p))
				if err != nil {
					return err
				}
			}

			r.infos[ref.ID()] = info

			return nil
		})
}

func (r directoryResolver) requestPath(userPath string) (string, error) {
	if filepath.IsAbs(userPath) {
		// don't allow input to potentially hop above root path
		userPath = path.Join(r.path, userPath)
	}
	var err error
	userPath, err = filepath.Abs(userPath)
	if err != nil {
		return "", nil
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

		references = append(references, NewLocation(r.responsePath(userStrPath)))
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
			result = append(result, NewLocation(r.responsePath(string(globResult.MatchPath))))
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
			results <- NewLocation(r.responsePath(string(ref.RealPath)))
		}
	}()
	return results
}

func (r *directoryResolver) FileMetadataByLocation(location Location) (FileMetadata, error) {
	info, exists := r.infos[location.ref.ID()]
	if !exists {
		return FileMetadata{}, fmt.Errorf("location: %+v : %w", location, os.ErrExist)
	}

	return FileMetadata{
		Mode: info.Mode(),
		Type: newFileTypeFromMode(info.Mode()),
		// unsupported across platforms
		UserID:  -1,
		GroupID: -1,
	}, nil
}

func isSystemRuntimePath(path string) bool {
	if internal.HasAnyOfPrefixes(path, systemRuntimePrefixes...) {
		return true
	}
	return false
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
