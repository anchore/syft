package golang

import (
	"io/fs"
	"path"
	"time"
)

type subFS struct {
	root string
	f    fs.FS
}

func getSubFS(f fs.FS, root string) fs.FS {
	if s, ok := f.(fs.SubFS); ok {
		s, err := s.Sub(root)
		if err != nil {
			return s
		}
	}

	return newSubFS(f, root)
}

func newSubFS(f fs.FS, root string) fs.FS {
	return subFS{
		root: root,
		f:    f,
	}
}

func (s subFS) Open(name string) (fs.File, error) {
	if name == "." {
		return rootFile{
			s: s,
		}, nil
	}
	return s.f.Open(path.Join(s.root, name))
}

type rootFile struct {
	s subFS
}

func (r rootFile) Name() string {
	return "."
}

func (r rootFile) Size() int64 {
	return 0
}

func (r rootFile) Mode() fs.FileMode {
	return fs.ModePerm
}

func (r rootFile) ModTime() time.Time {
	return time.Now()
}

func (r rootFile) IsDir() bool {
	return true
}

func (r rootFile) Sys() any {
	return nil
}

func (r rootFile) ReadDir(_ int) ([]fs.DirEntry, error) {
	return fs.ReadDir(r.s.f, r.s.root)
}

func (r rootFile) Stat() (fs.FileInfo, error) {
	return r, nil
}

func (r rootFile) Read(_ []byte) (int, error) {
	panic("not implemented")
}

func (r rootFile) Close() error {
	return nil
}

var _ fs.File = (*rootFile)(nil)
var _ fs.ReadDirFile = (*rootFile)(nil)
var _ fs.FileInfo = (*rootFile)(nil)

type subFsFileInfo struct {
	fi fs.FileInfo
}

func (s subFsFileInfo) Name() string {
	return s.fi.Name()
}

func (s subFsFileInfo) Size() int64 {
	return s.fi.Size()
}

func (s subFsFileInfo) Mode() fs.FileMode {
	return s.fi.Mode()
}

func (s subFsFileInfo) ModTime() time.Time {
	return s.fi.ModTime()
}

func (s subFsFileInfo) IsDir() bool {
	return s.fi.IsDir()
}

func (s subFsFileInfo) Sys() any {
	return s.fi.Sys()
}

var _ fs.FileInfo = (*subFsFileInfo)(nil)
