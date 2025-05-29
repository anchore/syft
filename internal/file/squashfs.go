package file

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/diskfs/go-diskfs/filesystem"
)

type WalkDiskDirFunc func(fsys filesystem.FileSystem, path string, d os.FileInfo, err error) error

// WalkDiskDir walks the file tree within the go-diskfs filesystem at root, calling fn for each file or directory in the tree, including root.
// This is meant to mimic the behavior of fs.WalkDir in the standard library.
func WalkDiskDir(fsys filesystem.FileSystem, root string, fn WalkDiskDirFunc) error {
	// First, try to get info about the root path
	infos, err := fsys.ReadDir(root)

	if err != nil {
		return err
	}

	if len(infos) == 0 {
		return fmt.Errorf("no entries in directory: %s", root)
	}

	for _, info := range infos {
		err = walkDiskDir(fsys, "/"+info.Name(), info, fn)
		if err == fs.SkipDir || err == fs.SkipAll {
			return nil
		}
	}

	return err
}

func walkDiskDir(fsys filesystem.FileSystem, name string, d os.FileInfo, walkDirFn WalkDiskDirFunc) error {
	if err := walkDirFn(fsys, name, d, nil); err != nil {
		if err == fs.SkipDir && (d == nil || d.IsDir()) {
			// successfully skipped directory.
			return nil
		}
		return err
	}

	// if d is nil, we need to determine if this is a directory by trying ReadDir
	isDir := d != nil && d.IsDir()
	if d == nil {
		// try to read as directory to determine if it's a directory
		_, err := fsys.ReadDir(name)
		if err != nil {
			// not a directory or error reading
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
			if err == fs.SkipDir {
				return nil
			}
			return err
		}
	}

	for _, d1 := range dirs {
		name1 := filepath.Join(name, d1.Name())
		if err := walkDiskDir(fsys, name1, d1, walkDirFn); err != nil {
			if err == fs.SkipDir {
				break
			}
			if err == fs.SkipAll {
				return err
			}
			return err
		}
	}
	return nil
}
