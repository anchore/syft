package golang

import (
	"io/fs"
	"os"

	"github.com/go-git/go-billy/v5"
)

// billyFSAdapter is a fs.FS, fs.ReadDirFS, and fs.StatFS wrapping what billyfs returns
type billyFSAdapter struct {
	fs billy.Filesystem
}

func (b billyFSAdapter) Stat(name string) (fs.FileInfo, error) {
	return b.fs.Stat(name)
}

func (b billyFSAdapter) ReadDir(name string) (out []fs.DirEntry, _ error) {
	entries, err := b.fs.ReadDir(name)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		out = append(out, billyDirEntry{fi: e})
	}
	return
}

func (b billyFSAdapter) Open(name string) (fs.File, error) {
	f, err := b.fs.Open(name)
	if err != nil {
		return nil, err
	}
	fi, err := b.Stat(name)
	if err != nil {
		return nil, err
	}
	return billyFile{f: f, fi: fi}, nil
}

var _ fs.FS = (*billyFSAdapter)(nil)
var _ fs.ReadDirFS = (*billyFSAdapter)(nil)
var _ fs.StatFS = (*billyFSAdapter)(nil)

// billyFile is a fs.File wrapping what billyfs returns
type billyFile struct {
	f  billy.File
	fi fs.FileInfo
}

func (b billyFile) Stat() (fs.FileInfo, error) {
	return b.fi, nil
}

func (b billyFile) Read(i []byte) (int, error) {
	return b.f.Read(i)
}

func (b billyFile) Close() error {
	return b.f.Close()
}

var _ fs.File = (*billyFile)(nil)

// billyDirEntry is a fs.DirEntry wrapping what billyfs returns
type billyDirEntry struct {
	fi os.FileInfo
}

func (b billyDirEntry) Name() string {
	return b.fi.Name()
}

func (b billyDirEntry) IsDir() bool {
	return b.fi.IsDir()
}

func (b billyDirEntry) Type() fs.FileMode {
	return b.fi.Mode()
}

func (b billyDirEntry) Info() (fs.FileInfo, error) {
	return b.fi, nil
}

var _ fs.DirEntry = (*billyDirEntry)(nil)
