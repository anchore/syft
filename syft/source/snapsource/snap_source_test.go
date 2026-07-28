package snapsource

import (
	"bytes"
	"crypto"
	"fmt"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/diskfs/go-diskfs/filesystem"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/go-homedir"
	stereoFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/event/monitor"
)

func TestNewFromLocal(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		setup       func(fs afero.Fs)
		wantRequest string
		wantErr     assert.ErrorAssertionFunc
	}{
		{
			name: "local file exists",
			cfg: Config{
				Request:          "/test/local.snap",
				DigestAlgorithms: []crypto.Hash{crypto.SHA256},
			},
			setup: func(fs afero.Fs) {
				require.NoError(t, createMockSquashfsFile(fs, "/test/local.snap"))
			},
			wantRequest: "/test/local.snap",
		},
		{
			name: "resolve home dir exists",
			cfg: Config{
				Request:          "~/test/local.snap",
				DigestAlgorithms: []crypto.Hash{crypto.SHA256},
			},
			wantErr: assert.Error,
			wantRequest: func() string {
				homeDir, err := homedir.Expand("~/test/local.snap")
				require.NoError(t, err, "failed to expand home directory")
				require.NotContains(t, homeDir, "~")
				return homeDir
			}(),
		},
		{
			name: "local file with architecture specified",
			cfg: Config{
				Request: "/test/local.snap",
				Platform: &image.Platform{
					Architecture: "arm64",
				},
			},
			setup: func(fs afero.Fs) {
				require.NoError(t, createMockSquashfsFile(fs, "/test/local.snap"))
			},
			wantErr: func(t assert.TestingT, err error, msgAndArgs ...any) bool {
				return assert.Error(t, err, msgAndArgs...) && assert.Contains(t, err.Error(), "architecture cannot be specified for local snap files", msgAndArgs...)
			},
			wantRequest: "/test/local.snap",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}
			tt.cfg.fs = afero.NewMemMapFs() // Use an in-memory filesystem for testing
			if tt.setup != nil {
				tt.setup(tt.cfg.fs)
			}
			got, err := getLocalSnapFile(&tt.cfg)
			tt.wantErr(t, err, fmt.Sprintf("NewFromLocal(%v)", tt.cfg))
			assert.Equal(t, tt.wantRequest, tt.cfg.Request, "expected request path to match")
			if err != nil {
				require.Nil(t, got, "expected nil source on error")
				return
			}
			require.NotNil(t, got, "expected non-nil source on success")

		})
	}
}

func Test_SquashfsSymlinkCrash(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		info         fakeFileInfo
		file         *fakeSquashFile
		wantType     stereoFile.Type
		wantLinkDest string
		wantMIME     assert.ValueAssertionFunc
	}{
		{
			// regression: previously the visitor opened every non-dir file and computed its MIME type
			// before inspecting the type, which consumed the symlink's reader so Readlink returned
			// nothing and the symlink was given a bogus MIME type. The fix only reads the link for
			// symlinks and only computes a MIME type for everything else.
			name: "symlink resolves link destination and is not given a mime type",
			path: "/link",
			info: fakeFileInfo{name: "link", mode: os.ModeSymlink | 0o777},
			// the reader returns content so that the (buggy) behavior of computing a MIME type would
			// have produced a non-empty MIME type, making this test fail against the old code.
			file:         &fakeSquashFile{Reader: bytes.NewReader([]byte("/usr/bin/target")), linkTarget: "/usr/bin/target"},
			wantType:     stereoFile.TypeSymLink,
			wantLinkDest: "/usr/bin/target",
			wantMIME:     assert.Empty,
		},
		{
			name:     "regular file is given a mime type",
			path:     "/file.txt",
			info:     fakeFileInfo{name: "file.txt", mode: 0o644, size: 11},
			file:     &fakeSquashFile{Reader: bytes.NewReader([]byte("hello world"))},
			wantType: stereoFile.TypeRegular,
			wantMIME: assert.NotEmpty,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := filetree.New()
			catalog := image.NewFileCatalog()
			prog := &monitor.TaskProgress{
				AtomicStage: progress.NewAtomicStage(""),
				Manual:      progress.NewManual(-1),
			}

			fsys := fakeSquashFS{openFile: func(string, int) (filesystem.File, error) {
				return tt.file, nil
			}}

			visit := squashfsVisitor(tree, catalog, nil, prog)
			require.NoError(t, visit(fsys, tt.path, tt.info, nil))

			entries, err := catalog.GetByBasename(tt.info.name)
			require.NoError(t, err)
			require.Len(t, entries, 1)

			entry := entries[0]
			assert.Equal(t, tt.wantType, entry.Metadata.Type)
			assert.Equal(t, tt.wantLinkDest, entry.Metadata.LinkDestination)
			tt.wantMIME(t, entry.Metadata.MIMEType)
		})
	}
}

// fakeFileInfo is a minimal os.FileInfo for driving squashfsVisitor in tests.
type fakeFileInfo struct {
	name string
	mode os.FileMode
	size int64
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

// fakeSquashFile implements filesystem.File and the linker interface used by squashfsVisitor.
type fakeSquashFile struct {
	*bytes.Reader
	linkTarget string
}

func (f *fakeSquashFile) Write([]byte) (int, error)  { return 0, fs.ErrInvalid }
func (f *fakeSquashFile) Close() error               { return nil }
func (f *fakeSquashFile) Stat() (fs.FileInfo, error) { return nil, fs.ErrInvalid }
func (f *fakeSquashFile) Readlink() (string, error)  { return f.linkTarget, nil }

// fakeSquashFS implements filesystem.FileSystem but only supports OpenFile; all other methods
// are inherited from the embedded nil interface and will panic if unexpectedly called.
type fakeSquashFS struct {
	filesystem.FileSystem
	openFile func(string, int) (filesystem.File, error)
}

func (f fakeSquashFS) OpenFile(name string, flag int) (filesystem.File, error) {
	return f.openFile(name, flag)
}
