package fileresolver

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/moby/sys/mountinfo"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/internal/windows"
)

type PathIndexVisitor func(string, string, os.FileInfo, error) error

type directoryIndexer struct {
	path              string
	base              string
	pathIndexVisitors []PathIndexVisitor
	errPaths          map[string]error
	tree              filetree.ReadWriter
	index             filetree.Index
}

func newDirectoryIndexer(path, base string, visitors ...PathIndexVisitor) *directoryIndexer {
	i := &directoryIndexer{
		path:  path,
		base:  base,
		tree:  filetree.New(),
		index: filetree.NewIndex(),
		pathIndexVisitors: append(
			[]PathIndexVisitor{
				requireFileInfo,
				disallowByFileType,
				newUnixSystemMountFinder().disallowUnixSystemRuntimePath},
			visitors...,
		),
		errPaths: make(map[string]error),
	}

	// these additional stateful visitors should be the first thing considered when walking / indexing
	i.pathIndexVisitors = append(
		[]PathIndexVisitor{
			i.disallowRevisitingVisitor,
			i.disallowFileAccessErr,
		},
		i.pathIndexVisitors...,
	)

	return i
}

func (r *directoryIndexer) build() (filetree.Reader, filetree.IndexReader, error) {
	return r.tree, r.index, indexAllRoots(r.path, r.indexTree)
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

func (r *directoryIndexer) indexTree(root string, stager *progress.Stage) ([]string, error) {
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

	shouldIndexFullTree, err := isRealPath(root)
	if err != nil {
		return nil, err
	}

	if !shouldIndexFullTree {
		newRoots, err := r.indexBranch(root, stager)
		if err != nil {
			return nil, fmt.Errorf("unable to index branch=%q: %w", root, err)
		}

		roots = append(roots, newRoots...)

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

	return roots, nil
}

func isRealPath(root string) (bool, error) {
	rootParent := filepath.Clean(filepath.Dir(root))

	realRootParent, err := filepath.EvalSymlinks(rootParent)
	if err != nil {
		return false, err
	}

	realRootParent = filepath.Clean(realRootParent)

	return rootParent == realRootParent, nil
}

func (r *directoryIndexer) indexBranch(root string, stager *progress.Stage) ([]string, error) {
	rootRealPath, err := filepath.EvalSymlinks(root)
	if err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			// we can't index the path, but we shouldn't consider this to be fatal
			// TODO: known-unknowns
			log.WithFields("root", root, "error", err).Trace("unable to evaluate symlink while indexing branch")
			return nil, nil
		}
		return nil, err
	}

	// there is a symlink within the path to the root, we need to index the real root parent first
	// then capture the symlinks to the root path
	roots, err := r.indexTree(rootRealPath, stager)
	if err != nil {
		return nil, fmt.Errorf("unable to index real root=%q: %w", rootRealPath, err)
	}

	// walk down all ancestor paths and shallow-add non-existing elements to the tree
	for idx, p := range allContainedPaths(root) {
		var targetPath string
		if idx != 0 {
			parent := path.Dir(p)
			cleanParent, err := filepath.EvalSymlinks(parent)
			if err != nil {
				return nil, fmt.Errorf("unable to evaluate symlink for contained path parent=%q: %w", parent, err)
			}
			targetPath = filepath.Join(cleanParent, filepath.Base(p))
		} else {
			targetPath = p
		}

		stager.Current = targetPath

		lstat, err := os.Lstat(targetPath)
		newRoot, err := r.indexPath(targetPath, lstat, err)
		if err != nil && !errors.Is(err, ErrSkipPath) && !errors.Is(err, fs.SkipDir) {
			return nil, fmt.Errorf("unable to index ancestor path=%q: %w", targetPath, err)
		}
		if newRoot != "" {
			roots = append(roots, newRoot)
		}
	}

	return roots, nil
}

func allContainedPaths(p string) []string {
	var all []string
	var currentPath string

	cleanPath := strings.TrimSpace(p)

	if cleanPath == "" {
		return nil
	}

	// iterate through all parts of the path, replacing path elements with link resolutions where possible.
	for idx, part := range strings.Split(filepath.Clean(cleanPath), file.DirSeparator) {
		if idx == 0 && part == "" {
			currentPath = file.DirSeparator
			continue
		}

		// cumulatively gather where we are currently at and provide a rich object
		currentPath = path.Join(currentPath, part)
		all = append(all, currentPath)
	}
	return all
}

func (r *directoryIndexer) indexPath(givenPath string, info os.FileInfo, err error) (string, error) {
	// ignore any path which a filter function returns true
	for _, filterFn := range r.pathIndexVisitors {
		if filterFn == nil {
			continue
		}

		if filterErr := filterFn(r.base, givenPath, info, err); filterErr != nil {
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
		r.errPaths[givenPath] = fmt.Errorf("no file info observable at path=%q", givenPath)
		return "", nil
	}

	// here we check to see if we need to normalize paths to posix on the way in coming from windows
	if windows.HostRunningOnWindows() {
		givenPath = windows.ToPosix(givenPath)
	}

	newRoot, err := r.addPathToIndex(givenPath, info)
	if r.isFileAccessErr(givenPath, err) {
		return "", nil
	}

	return newRoot, nil
}

func (r *directoryIndexer) disallowFileAccessErr(_, path string, _ os.FileInfo, err error) error {
	if r.isFileAccessErr(path, err) {
		return ErrSkipPath
	}
	return nil
}

func (r *directoryIndexer) isFileAccessErr(path string, err error) bool {
	// don't allow for errors to stop indexing, keep track of the paths and continue.
	if err != nil {
		log.Warnf("unable to access path=%q: %+v", path, err)
		r.errPaths[path] = err
		return true
	}
	return false
}

func (r directoryIndexer) addPathToIndex(p string, info os.FileInfo) (string, error) {
	switch t := file.TypeFromMode(info.Mode()); t {
	case file.TypeSymLink:
		return r.addSymlinkToIndex(p, info)
	case file.TypeDirectory:
		return "", r.addDirectoryToIndex(p, info)
	case file.TypeRegular:
		return "", r.addFileToIndex(p, info)
	default:
		return "", fmt.Errorf("unsupported file type: %s", t)
	}
}

func (r directoryIndexer) addDirectoryToIndex(p string, info os.FileInfo) error {
	ref, err := r.tree.AddDir(file.Path(p))
	if err != nil {
		return err
	}

	metadata := file.NewMetadataFromPath(p, info)
	r.index.Add(*ref, metadata)

	return nil
}

func (r directoryIndexer) addFileToIndex(p string, info os.FileInfo) error {
	ref, err := r.tree.AddFile(file.Path(p))
	if err != nil {
		return err
	}

	metadata := file.NewMetadataFromPath(p, info)
	r.index.Add(*ref, metadata)

	return nil
}

func (r directoryIndexer) addSymlinkToIndex(p string, info os.FileInfo) (string, error) {
	linkTarget, err := os.Readlink(p)
	if err != nil {
		isOnWindows := windows.HostRunningOnWindows()
		if isOnWindows {
			p = windows.FromPosix(p)
		}

		linkTarget, err = filepath.EvalSymlinks(p)

		if isOnWindows {
			p = windows.ToPosix(p)
		}

		if err != nil {
			return "", fmt.Errorf("unable to readlink for path=%q: %w", p, err)
		}
	}

	if filepath.IsAbs(linkTarget) {
		linkTarget = filepath.Clean(linkTarget)
		// if the link is absolute (e.g, /bin/ls -> /bin/busybox) we need to
		// resolve relative to the root of the base directory, if it is not already
		// prefixed with a volume name
		if filepath.VolumeName(linkTarget) == "" {
			linkTarget = filepath.Join(r.base, filepath.Clean(linkTarget))
		}
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

	ref, err := r.tree.AddSymLink(file.Path(p), file.Path(linkTarget))
	if err != nil {
		return "", err
	}

	targetAbsPath := linkTarget
	if !filepath.IsAbs(targetAbsPath) {
		targetAbsPath = filepath.Clean(filepath.Join(path.Dir(p), linkTarget))
	}

	metadata := file.NewMetadataFromPath(p, info)
	metadata.LinkDestination = linkTarget
	r.index.Add(*ref, metadata)

	// if the target path does not exist, then do not report it as a new root, or try to send
	// syft parsing there.
	if _, err := os.Stat(targetAbsPath); err != nil && errors.Is(err, os.ErrNotExist) {
		log.Debugf("link %s points to unresolved path %s, ignoring target as new root", p, targetAbsPath)
		targetAbsPath = ""
	}

	return targetAbsPath, nil
}

func (r directoryIndexer) hasBeenIndexed(p string) (bool, *file.Metadata) {
	filePath := file.Path(p)
	if !r.tree.HasPath(filePath) {
		return false, nil
	}

	exists, ref, err := r.tree.File(filePath)
	if err != nil || !exists || !ref.HasReference() {
		return false, nil
	}

	// cases like "/" will be in the tree, but not been indexed yet (a special case). We want to capture
	// these cases as new paths to index.
	if !ref.HasReference() {
		return false, nil
	}

	entry, err := r.index.Get(*ref.Reference)
	if err != nil {
		return false, nil
	}

	return true, &entry.Metadata
}

func (r *directoryIndexer) disallowRevisitingVisitor(_, path string, _ os.FileInfo, _ error) error {
	// this prevents visiting:
	// - link destinations twice, once for the real file and another through the virtual path
	// - infinite link cycles
	if indexed, metadata := r.hasBeenIndexed(path); indexed {
		if metadata.IsDir() {
			// signal to walk() that we should skip this directory entirely
			return fs.SkipDir
		}
		return ErrSkipPath
	}
	return nil
}

type unixSystemMountFinder struct {
	disallowedMountPaths []string
}

func newUnixSystemMountFinder() unixSystemMountFinder {
	infos, err := mountinfo.GetMounts(nil)
	if err != nil {
		log.WithFields("error", err).Warnf("unable to get system mounts")
		return unixSystemMountFinder{}
	}

	return unixSystemMountFinder{
		disallowedMountPaths: keepUnixSystemMountPaths(infos),
	}
}

func keepUnixSystemMountPaths(infos []*mountinfo.Info) []string {
	var mountPaths []string
	for _, info := range infos {
		if info == nil {
			continue
		}
		// we're only interested in ignoring the logical filesystems typically found at these mount points:
		// - /proc
		//     - procfs
		//     - proc
		// - /sys
		//     - sysfs
		// - /dev
		//     - devfs - BSD/darwin flavored systems and old linux systems
		//     - devtmpfs - driver core maintained /dev tmpfs
		//     - udev - userspace implementation that replaced devfs
		//     - tmpfs - used for /dev in special instances (within a container)

		switch info.FSType {
		case "proc", "procfs", "sysfs", "devfs", "devtmpfs", "udev", "tmpfs":
			log.WithFields("mountpoint", info.Mountpoint).Debug("ignoring system mountpoint")

			mountPaths = append(mountPaths, info.Mountpoint)
		}
	}
	return mountPaths
}

func (f unixSystemMountFinder) disallowUnixSystemRuntimePath(_, path string, _ os.FileInfo, _ error) error {
	if internal.HasAnyOfPrefixes(path, f.disallowedMountPaths...) {
		return fs.SkipDir
	}
	return nil
}

func disallowByFileType(_, _ string, info os.FileInfo, _ error) error {
	if info == nil {
		// we can't filter out by filetype for non-existent files
		return nil
	}
	switch file.TypeFromMode(info.Mode()) {
	case file.TypeCharacterDevice, file.TypeSocket, file.TypeBlockDevice, file.TypeFIFO, file.TypeIrregular:
		return ErrSkipPath
		// note: symlinks that point to these files may still get by.
		// We handle this later in processing to help prevent against infinite links traversal.
	}

	return nil
}

func requireFileInfo(_, _ string, info os.FileInfo, _ error) error {
	if info == nil {
		return ErrSkipPath
	}
	return nil
}

func indexingProgress(path string) (*progress.Stage, *progress.Manual) {
	stage := &progress.Stage{}
	prog := progress.NewManual(-1)

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
