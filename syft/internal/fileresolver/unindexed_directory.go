package fileresolver

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/afero"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

var _ file.Resolver = (*UnindexedDirectory)(nil)
var _ file.WritableResolver = (*UnindexedDirectory)(nil)

type UnindexedDirectory struct {
	ls   afero.Lstater
	lr   afero.LinkReader
	base string
	dir  string
	fs   afero.Fs
}

func NewFromUnindexedDirectory(dir string) file.WritableResolver {
	return NewFromUnindexedDirectoryFS(afero.NewOsFs(), dir, "")
}

func NewFromRootedUnindexedDirectory(dir string, base string) file.WritableResolver {
	return NewFromUnindexedDirectoryFS(afero.NewOsFs(), dir, base)
}

func NewFromUnindexedDirectoryFS(fs afero.Fs, dir string, base string) file.WritableResolver {
	ls, ok := fs.(afero.Lstater)
	if !ok {
		panic(fmt.Sprintf("unable to get afero.Lstater interface from: %+v", fs))
	}
	lr, ok := fs.(afero.LinkReader)
	if !ok {
		panic(fmt.Sprintf("unable to get afero.Lstater interface from: %+v", fs))
	}
	expanded, err := homedir.Expand(dir)
	if err == nil {
		dir = expanded
	}
	if base != "" {
		expanded, err = homedir.Expand(base)
		if err == nil {
			base = expanded
		}
	}
	wd, err := os.Getwd()
	if err == nil {
		if !path.IsAbs(dir) {
			dir = path.Clean(path.Join(wd, dir))
		}
		if base != "" && !path.IsAbs(base) {
			base = path.Clean(path.Join(wd, base))
		}
	}
	return UnindexedDirectory{
		base: base,
		dir:  dir,
		fs:   fs,
		ls:   ls,
		lr:   lr,
	}
}

func (u UnindexedDirectory) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	p := u.absPath(u.scrubInputPath(location.RealPath))
	f, err := u.fs.Open(p)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("unable to get contents of directory: %s", location.RealPath)
	}
	return f, nil
}

// - full symlink resolution should be performed on all requests
// - returns locations for any file or directory
func (u UnindexedDirectory) HasPath(p string) bool {
	locs, err := u.filesByPath(true, true, p)
	return err == nil && len(locs) > 0
}

func (u UnindexedDirectory) canLstat(p string) bool {
	_, _, err := u.ls.LstatIfPossible(u.absPath(p))
	return err == nil
}

func (u UnindexedDirectory) isRegularFile(p string) bool {
	fi, _, err := u.ls.LstatIfPossible(u.absPath(p))
	return err == nil && !fi.IsDir()
}

func (u UnindexedDirectory) scrubInputPath(p string) string {
	if path.IsAbs(p) {
		p = p[1:]
	}
	return path.Clean(p)
}

func (u UnindexedDirectory) scrubResolutionPath(p string) string {
	if u.base != "" {
		if path.IsAbs(p) {
			p = p[1:]
		}
		for strings.HasPrefix(p, "../") {
			p = p[3:]
		}
	}
	return path.Clean(p)
}

func (u UnindexedDirectory) absPath(p string) string {
	if u.base != "" {
		if path.IsAbs(p) {
			p = p[1:]
		}
		for strings.HasPrefix(p, "../") {
			p = p[3:]
		}
		p = path.Join(u.base, p)
		return path.Clean(p)
	}
	if path.IsAbs(p) {
		return p
	}
	return path.Clean(path.Join(u.dir, p))
}

// - full symlink resolution should be performed on all requests
// - only returns locations to files (NOT directories)
func (u UnindexedDirectory) FilesByPath(paths ...string) (out []file.Location, _ error) {
	return u.filesByPath(true, false, paths...)
}

func (u UnindexedDirectory) filesByPath(resolveLinks bool, includeDirs bool, paths ...string) (out []file.Location, _ error) {
	// sort here for stable output
	sort.Strings(paths)
nextPath:
	for _, p := range paths {
		p = u.scrubInputPath(p)
		if u.canLstat(p) && (includeDirs || u.isRegularFile(p)) {
			l := u.newLocation(p, resolveLinks)
			if l == nil {
				continue
			}
			// only include the first entry we find
			for i := range out {
				existing := &out[i]
				if existing.RealPath == l.RealPath {
					if l.VirtualPath == "" {
						existing.VirtualPath = ""
					}
					continue nextPath
				}
			}
			out = append(out, *l)
		}
	}
	return
}

// - full symlink resolution should be performed on all requests
// - if multiple paths to the same file are found, the best single match should be returned
// - only returns locations to files (NOT directories)
func (u UnindexedDirectory) FilesByGlob(patterns ...string) (out []file.Location, _ error) {
	return u.filesByGlob(true, false, patterns...)
}

func (u UnindexedDirectory) filesByGlob(resolveLinks bool, includeDirs bool, patterns ...string) (out []file.Location, _ error) {
	f := unindexedDirectoryResolverFS{
		u: u,
	}
	var paths []string
	for _, p := range patterns {
		opts := []doublestar.GlobOption{doublestar.WithNoFollow()}
		if !includeDirs {
			opts = append(opts, doublestar.WithFilesOnly())
		}
		found, err := doublestar.Glob(f, p, opts...)
		if err != nil {
			return nil, err
		}
		paths = append(paths, found...)
	}
	return u.filesByPath(resolveLinks, includeDirs, paths...)
}

func (u UnindexedDirectory) FilesByMIMEType(_ ...string) ([]file.Location, error) {
	panic("FilesByMIMEType unsupported")
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another file.
func (u UnindexedDirectory) RelativeFileByPath(l file.Location, p string) *file.Location {
	p = path.Clean(path.Join(l.RealPath, p))
	locs, err := u.filesByPath(true, false, p)
	if err != nil || len(locs) == 0 {
		return nil
	}
	l = locs[0]
	p = l.RealPath
	if u.isRegularFile(p) {
		return u.newLocation(p, true)
	}
	return nil
}

// - NO symlink resolution should be performed on results
// - returns locations for any file or directory
func (u UnindexedDirectory) AllLocations() <-chan file.Location {
	out := make(chan file.Location)
	go func() {
		defer close(out)
		err := afero.Walk(u.fs, u.absPath("."), func(p string, info fs.FileInfo, err error) error {
			p = strings.TrimPrefix(p, u.dir)
			if p == "" {
				return nil
			}
			p = strings.TrimPrefix(p, "/")
			out <- file.NewLocation(p)
			return nil
		})
		if err != nil {
			log.Debug(err)
		}
	}()
	return out
}

func (u UnindexedDirectory) FileMetadataByLocation(_ file.Location) (file.Metadata, error) {
	panic("FileMetadataByLocation unsupported")
}

func (u UnindexedDirectory) Write(location file.Location, reader io.Reader) error {
	filePath := location.RealPath
	if path.IsAbs(filePath) {
		filePath = filePath[1:]
	}
	absPath := u.absPath(filePath)
	return afero.WriteReader(u.fs, absPath, reader)
}

func (u UnindexedDirectory) newLocation(filePath string, resolveLinks bool) *file.Location {
	filePath = path.Clean(filePath)

	virtualPath := ""
	realPath := filePath

	if resolveLinks {
		paths := u.resolveLinks(filePath)
		if len(paths) > 1 {
			realPath = paths[len(paths)-1]
			if realPath != path.Clean(filePath) {
				virtualPath = paths[0]
			}
		}
		if len(paths) == 0 {
			// this file does not exist, don't return a location
			return nil
		}
	}

	l := file.NewVirtualLocation(realPath, virtualPath)
	return &l
}

//nolint:gocognit
func (u UnindexedDirectory) resolveLinks(filePath string) []string {
	var visited []string

	out := []string{}

	resolvedPath := ""

	parts := strings.Split(filePath, "/")
	for i := 0; i < len(parts); i++ {
		part := parts[i]
		if resolvedPath == "" {
			resolvedPath = part
		} else {
			resolvedPath = path.Clean(path.Join(resolvedPath, part))
		}
		resolvedPath = u.scrubResolutionPath(resolvedPath)
		if resolvedPath == ".." {
			resolvedPath = ""
			continue
		}

		absPath := u.absPath(resolvedPath)
		if slices.Contains(visited, absPath) {
			return nil // circular links can't resolve
		}
		visited = append(visited, absPath)

		fi, wasLstat, err := u.ls.LstatIfPossible(absPath)
		if fi == nil || err != nil {
			// this file does not exist
			return nil
		}

		for wasLstat && u.isSymlink(fi) {
			next, err := u.lr.ReadlinkIfPossible(absPath)
			if err == nil {
				if !path.IsAbs(next) {
					next = path.Clean(path.Join(path.Dir(resolvedPath), next))
				}
				next = u.scrubResolutionPath(next)
				absPath = u.absPath(next)
				if slices.Contains(visited, absPath) {
					return nil // circular links can't resolve
				}
				visited = append(visited, absPath)

				fi, wasLstat, err = u.ls.LstatIfPossible(absPath)
				if fi == nil || err != nil {
					// this file does not exist
					return nil
				}
				if i < len(parts) {
					out = append(out, path.Join(resolvedPath, path.Join(parts[i+1:]...)))
				}
				if u.base != "" && path.IsAbs(next) {
					next = next[1:]
				}
				resolvedPath = next
			}
		}
	}

	out = append(out, resolvedPath)

	return out
}

func (u UnindexedDirectory) isSymlink(fi os.FileInfo) bool {
	return fi.Mode().Type()&fs.ModeSymlink == fs.ModeSymlink
}

// ------------------------- fs.FS ------------------------------

// unindexedDirectoryResolverFS wraps the UnindexedDirectory as a fs.FS, fs.ReadDirFS, and fs.StatFS
type unindexedDirectoryResolverFS struct {
	u UnindexedDirectory
}

// resolve takes a virtual path and returns the resolved absolute or relative path and file info
func (f unindexedDirectoryResolverFS) resolve(filePath string) (resolved string, fi fs.FileInfo, err error) {
	parts := strings.Split(filePath, "/")
	var visited []string
	for i, part := range parts {
		if i > 0 {
			resolved = path.Clean(path.Join(resolved, part))
		} else {
			resolved = part
		}
		abs := f.u.absPath(resolved)
		fi, _, err = f.u.ls.LstatIfPossible(abs)
		if err != nil {
			return resolved, fi, err
		}
		for f.u.isSymlink(fi) {
			if slices.Contains(visited, resolved) {
				return resolved, fi, fmt.Errorf("link cycle detected at: %s", f.u.absPath(resolved))
			}
			visited = append(visited, resolved)
			link, err := f.u.lr.ReadlinkIfPossible(abs)
			if err != nil {
				return resolved, fi, err
			}
			if !path.IsAbs(link) {
				link = path.Clean(path.Join(path.Dir(abs), link))
				link = strings.TrimPrefix(link, abs)
			} else if f.u.base != "" {
				link = path.Clean(path.Join(f.u.base, link[1:]))
			}
			resolved = link
			abs = f.u.absPath(resolved)
			fi, _, err = f.u.ls.LstatIfPossible(abs)
			if err != nil {
				return resolved, fi, err
			}
		}
	}
	return resolved, fi, err
}

func (f unindexedDirectoryResolverFS) ReadDir(name string) (out []fs.DirEntry, _ error) {
	p, _, err := f.resolve(name)
	if err != nil {
		return nil, err
	}
	entries, err := afero.ReadDir(f.u.fs, f.u.absPath(p))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		isDir := e.IsDir()
		_, fi, _ := f.resolve(path.Join(name, e.Name()))
		if fi != nil && fi.IsDir() {
			isDir = true
		}
		out = append(out, unindexedDirectoryResolverDirEntry{
			unindexedDirectoryResolverFileInfo: newFsFileInfo(f.u, e.Name(), isDir, e),
		})
	}
	return out, nil
}

func (f unindexedDirectoryResolverFS) Stat(name string) (fs.FileInfo, error) {
	fi, err := f.u.fs.Stat(f.u.absPath(name))
	if err != nil {
		return nil, err
	}
	return newFsFileInfo(f.u, name, fi.IsDir(), fi), nil
}

func (f unindexedDirectoryResolverFS) Open(name string) (fs.File, error) {
	_, err := f.u.fs.Open(f.u.absPath(name))
	if err != nil {
		return nil, err
	}

	return unindexedDirectoryResolverFile{
		u:    f.u,
		path: name,
	}, nil
}

var _ fs.FS = (*unindexedDirectoryResolverFS)(nil)
var _ fs.StatFS = (*unindexedDirectoryResolverFS)(nil)
var _ fs.ReadDirFS = (*unindexedDirectoryResolverFS)(nil)

type unindexedDirectoryResolverDirEntry struct {
	unindexedDirectoryResolverFileInfo
}

func (f unindexedDirectoryResolverDirEntry) Name() string {
	return f.name
}

func (f unindexedDirectoryResolverDirEntry) IsDir() bool {
	return f.isDir
}

func (f unindexedDirectoryResolverDirEntry) Type() fs.FileMode {
	return f.mode
}

func (f unindexedDirectoryResolverDirEntry) Info() (fs.FileInfo, error) {
	return f, nil
}

var _ fs.DirEntry = (*unindexedDirectoryResolverDirEntry)(nil)

type unindexedDirectoryResolverFile struct {
	u    UnindexedDirectory
	path string
}

func (f unindexedDirectoryResolverFile) Stat() (fs.FileInfo, error) {
	fi, err := f.u.fs.Stat(f.u.absPath(f.path))
	if err != nil {
		return nil, err
	}
	return newFsFileInfo(f.u, fi.Name(), fi.IsDir(), fi), nil
}

func (f unindexedDirectoryResolverFile) Read(_ []byte) (int, error) {
	panic("Read not implemented")
}

func (f unindexedDirectoryResolverFile) Close() error {
	panic("Close not implemented")
}

var _ fs.File = (*unindexedDirectoryResolverFile)(nil)

type unindexedDirectoryResolverFileInfo struct {
	u       UnindexedDirectory
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
	sys     any
}

func newFsFileInfo(u UnindexedDirectory, name string, isDir bool, fi os.FileInfo) unindexedDirectoryResolverFileInfo {
	return unindexedDirectoryResolverFileInfo{
		u:       u,
		name:    name,
		size:    fi.Size(),
		mode:    fi.Mode() & ^fs.ModeSymlink, // pretend nothing is a symlink
		modTime: fi.ModTime(),
		isDir:   isDir,
		// sys:     fi.Sys(), // what values does this hold?
	}
}

func (f unindexedDirectoryResolverFileInfo) Name() string {
	return f.name
}

func (f unindexedDirectoryResolverFileInfo) Size() int64 {
	return f.size
}

func (f unindexedDirectoryResolverFileInfo) Mode() fs.FileMode {
	return f.mode
}

func (f unindexedDirectoryResolverFileInfo) ModTime() time.Time {
	return f.modTime
}

func (f unindexedDirectoryResolverFileInfo) IsDir() bool {
	return f.isDir
}

func (f unindexedDirectoryResolverFileInfo) Sys() any {
	return f.sys
}

var _ fs.FileInfo = (*unindexedDirectoryResolverFileInfo)(nil)
