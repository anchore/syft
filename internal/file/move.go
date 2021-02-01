package file

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/spf13/afero"
)

func MoveDir(fs afero.Fs, src string, dst string) error {
	var err error
	var fds []os.FileInfo
	var srcinfo os.FileInfo

	if srcinfo, err = fs.Stat(src); err != nil {
		return err
	}

	if err = fs.MkdirAll(dst, srcinfo.Mode()); err != nil {
		return err
	}

	if fds, err = ioutil.ReadDir(src); err != nil {
		return err
	}
	for _, fd := range fds {
		srcPath := path.Join(src, fd.Name())
		dstPath := path.Join(dst, fd.Name())

		if fd.IsDir() {
			if err = fs.Rename(srcPath, dstPath); err != nil {
				return fmt.Errorf("could not move dir (%s -> %s): %w", srcPath, dstPath, err)
			}
		} else {
			if err = fs.Rename(srcPath, dstPath); err != nil {
				return fmt.Errorf("could not move file (%s -> %s): %w", srcPath, dstPath, err)
			}
		}
	}
	return nil
}
