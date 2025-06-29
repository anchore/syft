package fileresolver

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/wagoodman/go-progress"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/internal/windows"
)

type fileIndexer struct {
	path              string
	base              string
	pathIndexVisitors []PathIndexVisitor
	errPaths          map[string]error
	tree              filetree.ReadWriter
	index             filetree.Index
}

func newFileIndexer(path, base string, visitors ...PathIndexVisitor) *fileIndexer {
	i := &fileIndexer{
		path:  path,
		base:  base,
		tree:  filetree.New(),
		index: filetree.NewIndex(),
		pathIndexVisitors: append(
			[]PathIndexVisitor{
				requireFileInfo,
				disallowByFileType,
				skipPathsByMountTypeAndName(path),
			},
			visitors...,
		),
		errPaths: make(map[string]error),
	}

	return i
}

// Build the indexer
func (r *fileIndexer) build() (filetree.Reader, filetree.IndexReader, error) {
	return r.tree, r.index, index(r.path, r.indexPath)
}

// Index file at the given path
// A file indexer simply indexes the file and its directory.
func index(path string, indexer func(string, *progress.AtomicStage) error) error {
	// We want to index the file at the provided path and its parent directory.
	// We need to probably check that we have file access
	// We also need to determine what to do when the file itself is a symlink.
	prog := bus.StartIndexingFiles(path)
	defer prog.SetCompleted()

	err := indexer(path, prog.AtomicStage)
	if err != nil {
		return fmt.Errorf("unable to index filesystem path=%q: %w", path, err)
	}

	return nil
}

// indexPath will index the file at the provided path as well as its parent directory.
// It expects path to be a file, not a directory.
// If a directory is provided then an error will be returned. Additionally, any IO or
// permissions errors on the file at path or its parent directory will return an error.
// Filter functions provided to the indexer are honoured, so if the path provided (or its parent
// directory) is filtered by a filter function, an error is returned.
func (r *fileIndexer) indexPath(path string, stager *progress.AtomicStage) error {
	log.WithFields("path", path).Trace("indexing file path")

	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	// Protect against callers trying to call file_indexer with directories
	fi, err := os.Stat(absPath)
	// The directory indexer ignores stat errors, however this file indexer won't ignore them
	if err != nil {
		return fmt.Errorf("unable to stat path=%q: %w", path, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("unable to index file, given path was a directory=%q", path)
	}

	absSymlinkFreeFilePath, err := absoluteSymlinkFreePathToFile(path)
	if err != nil {
		return err
	}

	// Now index the file and its parent directory
	// We try to index the parent directory first, because if the parent directory
	// is ignored by any filter function, then we must ensure we also ignore the file.
	absSymlinkFreeParent, err := absoluteSymlinkFreePathToParent(absSymlinkFreeFilePath)
	if err != nil {
		return err
	}
	parentFi, err := os.Stat(absSymlinkFreeParent)
	if err != nil {
		return fmt.Errorf("unable to stat parent of file=%q: %w", absSymlinkFreeParent, err)
	}

	stager.Set(absSymlinkFreeParent)
	indexParentErr := r.filterAndIndex(absSymlinkFreeParent, parentFi)
	if indexParentErr != nil {
		return indexParentErr
	}

	// We have indexed the parent successfully, now attempt to index the file.
	stager.Set(absSymlinkFreeFilePath)
	indexFileErr := r.filterAndIndex(absSymlinkFreeFilePath, fi)
	if indexFileErr != nil {
		return indexFileErr
	}

	return nil
}

func (r *fileIndexer) filterAndIndex(path string, info os.FileInfo) error {
	// check if any of the filters want us to ignore this path
	for _, filterFn := range r.pathIndexVisitors {
		if filterFn == nil {
			continue
		}

		if filterErr := filterFn(r.base, path, info, nil); filterErr != nil {
			// A filter function wants us to ignore this path, honour it
			return filterErr
		}
	}

	// here we check to see if we need to normalize paths to posix on the way in coming from windows
	if windows.HostRunningOnWindows() {
		path = windows.ToPosix(path)
	}

	err := r.addPathToIndex(path, info)
	// If we hit file access errors, isFileAccessErr will handle logging & adding
	// the path to the errPaths map.
	// While the directory_indexer does not let these cause the indexer to throw
	// we will here, as not having access to the file we index for a file source
	// probably makes the file source creation useless? I need to check with Syft maintainers.
	// This also poses the question, is errPaths worthwhile for file_indexer?
	if r.isFileAccessErr(path, err) {
		return err
	}

	return nil
}

// Add path to index. File indexer doesn't need to support symlink, as we should have abs symlink free path.
// If we somehow get a symlink here, report as an error.
func (r *fileIndexer) addPathToIndex(path string, info os.FileInfo) error {
	switch t := file.TypeFromMode(info.Mode()); t {
	case file.TypeDirectory:
		return r.addDirectoryToIndex(path, info)
	case file.TypeRegular:
		return r.addFileToIndex(path, info)
	default:
		return fmt.Errorf("unsupported file type: %s", t)
	}
}

func (r *fileIndexer) addDirectoryToIndex(path string, info os.FileInfo) error {
	ref, err := r.tree.AddDir(file.Path(path))
	if err != nil {
		return err
	}

	metadata := file.NewMetadataFromPath(path, info)
	r.index.Add(*ref, metadata)

	return nil
}

func (r *fileIndexer) addFileToIndex(path string, info os.FileInfo) error {
	ref, err := r.tree.AddFile(file.Path(path))
	if err != nil {
		return err
	}

	metadata := file.NewMetadataFromPath(path, info)
	r.index.Add(*ref, metadata)

	return nil
}

// Get absolute symlink free path to parent of the file
func absoluteSymlinkFreePathToParent(path string) (string, error) {
	absFilePath, err := absoluteSymlinkFreePathToFile(path)
	if err != nil {
		return "", err
	}

	return filepath.Dir(absFilePath), nil
}

// Get absolute symlink free path to the file
func absoluteSymlinkFreePathToFile(path string) (string, error) {
	absAnalysisPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("unable to get absolute path for analysis path=%q: %w", path, err)
	}
	dereferencedAbsAnalysisPath, err := filepath.EvalSymlinks(absAnalysisPath)
	if err != nil {
		return "", fmt.Errorf("unable to get absolute path for analysis path=%q: %w", path, err)
	}
	return dereferencedAbsAnalysisPath, nil
}

func (r *fileIndexer) isFileAccessErr(path string, err error) bool {
	// don't allow for errors to stop indexing, keep track of the paths and continue.
	if err != nil {
		log.Warnf("unable to access path=%q: %+v", path, err)
		r.errPaths[path] = err
		return true
	}
	return false
}
