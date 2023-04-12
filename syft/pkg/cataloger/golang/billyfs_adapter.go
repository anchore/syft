package golang

import (
	"io/fs"
	"os"

	"github.com/go-git/go-billy/v5"
)

type bfs struct {
	fs billy.Filesystem
}

func (b bfs) Stat(name string) (fs.FileInfo, error) {
	return b.fs.Stat(name)
}

func (b bfs) ReadDir(name string) (out []fs.DirEntry, _ error) {
	entries, err := b.fs.ReadDir(name)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		out = append(out, bdir{fi: e})
	}
	return
}

func (b bfs) Open(name string) (fs.File, error) {
	f, err := b.fs.Open(name)
	if err != nil {
		return nil, err
	}
	fi, err := b.Stat(name)
	if err != nil {
		return nil, err
	}
	return bfile{f: f, fi: fi}, nil
}

var _ fs.FS = (*bfs)(nil)
var _ fs.ReadDirFS = (*bfs)(nil)
var _ fs.StatFS = (*bfs)(nil)

type bfile struct {
	f  billy.File
	fi fs.FileInfo
}

func (b bfile) Stat() (fs.FileInfo, error) {
	return b.fi, nil
}

func (b bfile) Read(i []byte) (int, error) {
	return b.f.Read(i)
}

func (b bfile) Close() error {
	return b.f.Close()
}

var _ fs.File = (*bfile)(nil)

type bdir struct {
	fi os.FileInfo
}

func (b bdir) Name() string {
	return b.fi.Name()
}

func (b bdir) IsDir() bool {
	return b.fi.IsDir()
}

func (b bdir) Type() fs.FileMode {
	return b.fi.Mode()
}

func (b bdir) Info() (fs.FileInfo, error) {
	return b.fi, nil
}

var _ fs.DirEntry = (*bdir)(nil)
