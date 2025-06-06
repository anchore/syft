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

	for _, info := range infos {
		p := filepath.Join(root, info.Name())
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

	for _, d1 := range dirs {
		name1 := filepath.Join(name, d1.Name())
		if err := walkDiskDir(fsys, name1, d1, walkDirFn); err != nil {
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
