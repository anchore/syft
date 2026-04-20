package file

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/diskfs/go-diskfs/filesystem"
)

type WalkDiskDirFunc func(fsys filesystem.FileSystem, path string, d os.FileInfo, err error) error

// WalkDiskDir walks the file tree within the go-diskfs filesystem at root, calling fn for each file or directory in the tree, including root.
// This is meant to mimic the behavior of fs.WalkDir in the standard library.
func WalkDiskDir(fsys filesystem.FileSystem, root string, fn WalkDiskDirFunc) error {
	infos, err := fsys.ReadDir(root)

	if err != nil {
		return err
	}

	if len(infos) == 0 {
		return nil
	}

	for _, entry := range infos {
		// fs.DirEntry no longer satisfies os.FileInfo in Go 1.26+
		// (ModTime moved off of DirEntry), so materialize the FileInfo
		// via Info() before passing it down.
		info, err := dirEntryInfo(entry)
		if err != nil {
			return err
		}
		p := filepath.Join(root, entry.Name())
		err = walkDiskDir(fsys, p, info, fn)
		if err != nil {
			if errors.Is(err, fs.SkipDir) {
				continue
			}
			if errors.Is(err, fs.SkipAll) {
				return nil
			}
			return err
		}
	}

	return err
}

func walkDiskDir(fsys filesystem.FileSystem, name string, d os.FileInfo, walkDirFn WalkDiskDirFunc) error {
	if err := walkDirFn(fsys, name, d, nil); err != nil {
		if errors.Is(err, fs.SkipDir) && (d == nil || d.IsDir()) {
			return nil
		}
		return err
	}

	isDir := d != nil && d.IsDir()
	if d == nil {
		_, err := fsys.ReadDir(name)
		if err != nil {
			return nil
		}
		isDir = true
	}

	if !isDir {
		return nil
	}

	dirs, err := fsys.ReadDir(name)
	if err != nil {
		err = walkDirFn(fsys, name, d, err)
		if err != nil {
			if errors.Is(err, fs.SkipDir) {
				return nil
			}
			return err
		}
	}

	for _, entry := range dirs {
		info, err := dirEntryInfo(entry)
		if err != nil {
			return err
		}
		name1 := filepath.Join(name, entry.Name())
		if err := walkDiskDir(fsys, name1, info, walkDirFn); err != nil {
			if errors.Is(err, fs.SkipDir) {
				break
			}
			if errors.Is(err, fs.SkipAll) {
				return err
			}
			return err
		}
	}
	return nil
}

// dirEntryInfo returns an os.FileInfo for the given fs.DirEntry, preserving
// the previous behavior where DirEntry values were passed where FileInfo
// was expected. As of Go 1.26, fs.DirEntry no longer implements
// os.FileInfo (ModTime was removed), so an explicit Info() call is
// required.
func dirEntryInfo(entry fs.DirEntry) (os.FileInfo, error) {
	if entry == nil {
		return nil, nil
	}
	if info, ok := entry.(os.FileInfo); ok {
		return info, nil
	}
	return entry.Info()
}
