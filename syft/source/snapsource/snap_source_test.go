package snapsource

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	diskFile "github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/filesystem/squashfs"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/go-homedir"
	stereoFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/source"
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

func TestNewFromPathOnResolverError(t *testing.T) {
	tests := []struct {
		name string
		// remote snaps carry a cleanup closure for the temp directory holding the download; local snaps
		// have none, since the file belongs to the user
		remote          bool
		wantCleanupRuns int
		wantFileRemoved bool
	}{
		{
			name:            "downloaded snap is cleaned up",
			remote:          true,
			wantCleanupRuns: 1,
			wantFileRemoved: true,
		},
		{
			name:            "local snap file is left in place",
			remote:          false,
			wantCleanupRuns: 0,
			wantFileRemoved: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the resolver reads the squashfs from the real filesystem, so the payload must live on disk
			tempDir := t.TempDir()
			snapPath := filepath.Join(tempDir, "not-really-a-snap.snap")
			require.NoError(t, os.WriteFile(snapPath, []byte("not squashfs"), 0600))

			var cleanupRuns int
			f := &snapFile{
				Path:     snapPath,
				MimeType: "text/plain",
			}
			if tt.remote {
				f.Cleanup = func() error {
					cleanupRuns++
					return os.RemoveAll(tempDir)
				}
			}

			got, err := newFromPath(Config{Request: snapPath}, f)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "unable to create snap file resolver")

			// a source returned alongside an error is discarded by callers without being closed, which
			// would leave the downloaded snap behind
			assert.Nil(t, got, "expected nil source on error")
			assert.Equal(t, tt.wantCleanupRuns, cleanupRuns)

			_, statErr := os.Stat(snapPath)
			if tt.wantFileRemoved {
				assert.True(t, os.IsNotExist(statErr), "snap file was not cleaned up")
			} else {
				assert.NoError(t, statErr, "the user's snap file must never be removed")
			}
		})
	}
}

// a manifest problem must never fail the source: snapsource is the only provider that can descend
// into squashfs, so an error here falls through to filesource and every package inside the payload
// silently disappears from the SBOM.
func TestNewFromPathToleratesManifestProblems(t *testing.T) {
	tests := []struct {
		name        string
		manifest    string // written to /meta/snap.yaml; empty means no manifest at all
		wantName    string
		wantVersion string
		wantSummary string
	}{
		{
			name:     "no manifest at all",
			manifest: "",
		},
		{
			name:     "manifest is not valid yaml",
			manifest: "name: etcd\n\tversion: 3.4\n",
		},
		{
			name:        "manifest is missing name and version",
			manifest:    "summary: a thing\nbase: core22\n",
			wantSummary: "a thing",
		},
		{
			name:        "manifest is complete",
			manifest:    "name: etcd\nversion: 3.4.0\nsummary: a thing\n",
			wantName:    "etcd",
			wantVersion: "3.4.0",
			wantSummary: "a thing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snapPath := writeSquashfs(t, tt.manifest)

			src, err := newFromPath(Config{Request: snapPath}, &snapFile{Path: snapPath})
			require.NoError(t, err, "a manifest problem must not fail the source")
			require.NotNil(t, src)
			t.Cleanup(func() { _ = src.Close() })

			desc := src.Describe()
			assert.Equal(t, tt.wantName, desc.Name)
			assert.Equal(t, tt.wantVersion, desc.Version)

			meta, ok := desc.Metadata.(source.SnapMetadata)
			require.True(t, ok, "expected snap metadata")
			assert.Equal(t, tt.wantSummary, meta.Summary, "fields that did decode must survive")

			// the whole point: the payload is still walkable, so cataloging sees what is inside
			r, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)
			locations, err := r.FilesByPath("/payload.txt")
			require.NoError(t, err)
			assert.Len(t, locations, 1, "contents must remain catalogable regardless of the manifest")
		})
	}
}

func TestSnapSourceClose(t *testing.T) {
	newSource := func(closeErr, cleanupErr error) (*snapSource, *int) {
		var cleanupRuns int
		return &snapSource{
			mutex: &sync.Mutex{},
			squashFileCloser: func() error {
				return closeErr
			},
			closer: func() error {
				cleanupRuns++
				return cleanupErr
			},
		}, &cleanupRuns
	}

	t.Run("temp directory is removed even when closing the file handle fails", func(t *testing.T) {
		s, cleanupRuns := newSource(errors.New("handle is busy"), nil)

		err := s.Close()

		// the whole point: a failure here used to return early and skip the cleanup below, leaving a
		// downloaded snap on disk
		require.Error(t, err)
		assert.Contains(t, err.Error(), "handle is busy")
		assert.Equal(t, 1, *cleanupRuns, "temp directory removal was skipped")
	})

	t.Run("every failure is reported, not just the first", func(t *testing.T) {
		s, _ := newSource(errors.New("handle is busy"), errors.New("directory is busy"))

		err := s.Close()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "handle is busy")
		assert.Contains(t, err.Error(), "directory is busy")
	})

	t.Run("is safe to call twice", func(t *testing.T) {
		s, cleanupRuns := newSource(nil, nil)

		require.NoError(t, s.Close())
		require.NoError(t, s.Close())
		assert.Equal(t, 1, *cleanupRuns, "cleanup must not run again on a second close")
	})
}

// writeSquashfs builds a real squashfs image containing /payload.txt and, when manifest is non-empty,
// /meta/snap.yaml. Returns the path to the image.
func writeSquashfs(t *testing.T, manifest string) string {
	t.Helper()

	snapPath := filepath.Join(t.TempDir(), "test.snap")
	f, err := os.Create(snapPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()

	fs, err := squashfs.Create(diskFile.New(f, false), 0, 0, 4096)
	require.NoError(t, err)

	write := func(path, contents string) {
		t.Helper()
		w, err := fs.OpenFile(path, os.O_CREATE|os.O_RDWR)
		require.NoError(t, err)
		_, err = w.Write([]byte(contents))
		require.NoError(t, err)
	}

	// note: go-diskfs wants paths relative to the image root, without a leading slash
	require.NoError(t, fs.Mkdir("."))
	write("payload.txt", "hello")

	if manifest != "" {
		require.NoError(t, fs.Mkdir("meta"))
		write(strings.TrimPrefix(manifestLocation, "/"), manifest)
	}

	require.NoError(t, fs.Finalize(squashfs.FinalizeOptions{}))
	return snapPath
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
