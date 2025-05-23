package file

import (
	"fmt"
	"github.com/diskfs/go-diskfs/filesystem"
	"io/fs"
	"os"
	"path/filepath"
)

//type SquashFSVisitor func(fsys filesystem.FileSystem, sqfsPath, filePath string) error

// WalkSquashFS walks the file tree within the SquashFS filesystem at sqfsPath, calling fn for each
// file or directory in the tree, including root.
//func WalkSquashFS(sqfsPath string, fn WalkDirFunc) error {
//
//
//	return WalkDir(fs, ".", fn)
//}

// walkDir returns a fs.WalkDirFunc bound to fn.
//func walkDir(fsys filesystem.FileSystem, sqfsPath string, fn SquashFSVisitor) fs.WalkDirFunc {
//	return func(path string, _ fs.DirEntry, err error) error {
//		if err != nil {
//			return err
//		}
//
//		return fn(fsys, sqfsPath, path)
//	}
//}

// WalkDirFunc is the type of the function called by WalkDir to visit
// each file or directory.
//
// The path argument contains the argument to WalkDir as a prefix.
// That is, if WalkDir is called with root argument "dir" and finds a file
// named "a" in that directory, the walk function will be called with
// argument "dir/a".
//
// The d argument is the fs.DirEntry for the named path.
//
// The error result returned by the function controls how WalkDir
// continues. If the function returns the special value SkipDir, WalkDir
// skips the current directory (path if d.IsDir() is true, otherwise
// path's parent directory). If the function returns the special value
// SkipAll, WalkDir skips all remaining files and directories. Otherwise,
// if the function returns a non-nil error, WalkDir stops entirely and
// returns that error.
//
// The err argument reports an error related to path, signaling that WalkDir
// will not walk into that directory. The function can decide how to
// handle that error; as described in the documentation for WalkDir, returning
// the error will cause WalkDir to stop walking the entire tree.
type WalkDirFunc func(fsys filesystem.FileSystem, path string, d os.FileInfo, err error) error

func WalkDir(fsys filesystem.FileSystem, root string, fn WalkDirFunc) error {
	// First, try to get info about the root path
	infos, err := fsys.ReadDir(root)

	if err != nil {
		return err
	}

	if len(infos) == 0 {
		return fmt.Errorf("no entries in directory: %s", root)
	}

	err = walkDir(fsys, root, infos[0], fn)

	if err == fs.SkipDir || err == fs.SkipAll {
		return nil
	}
	return err
}

// walkDir recursively descends path, calling walkDirFn.
func walkDir(fsys filesystem.FileSystem, name string, d os.FileInfo, walkDirFn WalkDirFunc) error {
	if err := walkDirFn(fsys, name, d, nil); err != nil {
		if err == fs.SkipDir && (d == nil || d.IsDir()) {
			// Successfully skipped directory.
			return nil
		}
		return err
	}

	// If d is nil, we need to determine if this is a directory by trying ReadDir
	isDir := d != nil && d.IsDir()
	if d == nil {
		// Try to read as directory to determine if it's a directory
		_, err := fsys.ReadDir(name)
		if err != nil {
			// Not a directory or error reading
			return nil
		}
		isDir = true
	}

	if !isDir {
		return nil
	}

	dirs, err := fsys.ReadDir(name)
	if err != nil {
		// Second call, to report ReadDir error.
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
		if err := walkDir(fsys, name1, d1, walkDirFn); err != nil {
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
