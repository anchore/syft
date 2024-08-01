package xfs_test

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/masahiro331/go-xfs-filesystem/xfs"
	"golang.org/x/xerrors"
)

func TestFileSystemCheckFileExtents(t *testing.T) {
	testFileCace := []struct {
		filesystem   string
		name         string
		expectedSize int
		mode         os.FileMode
		expectedErr  error
	}{
		{
			filesystem:   "testdata/image.xfs",
			name:         "fmt_extents_file_1024",
			expectedSize: 1024,
			mode:         33188,
		},
		{
			filesystem:   "testdata/image.xfs",
			name:         "fmt_extents_file_4096",
			expectedSize: 4096,
			mode:         33188,
		},
		{
			filesystem:   "testdata/image.xfs",
			name:         "fmt_extents_file_16384",
			expectedSize: 16384,
			mode:         33188,
		},
		{
			filesystem:  "testdata/image.xfs",
			name:        "no_exist_file",
			expectedErr: fmt.Errorf("file does not exist"),
		},
		{
			filesystem:  "testdata/image.xfs",
			name:        "no_exist_directory/no_exist_file",
			expectedErr: fmt.Errorf("file does not exist"),
		},
	}

	for _, tt := range testFileCace {
		t.Run(fmt.Sprintf("test %s read", tt.name), func(t *testing.T) {
			f, err := os.Open(tt.filesystem)
			if err != nil {
				t.Fatal(err)
			}
			info, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}

			fileSystem, err := xfs.NewFS(*io.NewSectionReader(f, 0, info.Size()), nil)
			if err != nil {
				t.Fatal(err)
			}

			testFile, err := fileSystem.Open(tt.name)
			if err != nil {
				if tt.expectedErr == nil {
					t.Fatal(err)
				}
				if !strings.Contains(err.Error(), tt.expectedErr.Error()) {
					t.Fatalf("name: %s, expected: %s, actual %s", tt.name, tt.expectedErr.Error(), err.Error())
				}
				return
			}

			stat, err := testFile.Stat()
			if err != nil {
				t.Fatal(err)
			}

			if stat.Size() != int64(tt.expectedSize) {
				t.Errorf("expected %d, actual %d", tt.expectedSize, stat.Size())
			}
			if stat.Name() != tt.name {
				t.Errorf("expected %s, actual %s", tt.name, stat.Name())
			}
			if stat.Mode() != tt.mode {
				t.Errorf("expected %s, actual %s", tt.mode, stat.Mode())
			}
		})
	}
}

func TestFileSystemCheckWalkDir(t *testing.T) {
	testExecutableFileCases := []struct {
		filesystem    string
		name          string
		parentPath    string
		expectedFiles []string
	}{
		{
			filesystem: "testdata/image.xfs",
			name:       "search executable file",
			parentPath: "parent",
			expectedFiles: []string{
				"parent/child/child/child/child/child/executable",
				"parent/child/child/child/child/executable",
			},
		},
		{
			filesystem: "testdata/image.xfs",
			name:       "search executable file with root node",
			parentPath: "/",
			expectedFiles: []string{
				"/parent/child/child/child/child/child/executable",
				"/parent/child/child/child/child/executable",
			},
		},
		{
			filesystem: "testdata/image.xfs",
			name:       "search executable file with deep path",
			parentPath: "/parent/child/child/child/child/child/",
			expectedFiles: []string{
				"/parent/child/child/child/child/child/executable",
			},
		},
	}

	for _, tt := range testExecutableFileCases {
		t.Run(fmt.Sprintf(tt.name), func(t *testing.T) {
			f, err := os.Open(tt.filesystem)
			if err != nil {
				t.Fatal(err)
			}
			info, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}

			fileSystem, err := xfs.NewFS(*io.NewSectionReader(f, 0, info.Size()), nil)
			if err != nil {
				t.Fatal(err)
			}

			filePaths := []string{}
			err = fs.WalkDir(fileSystem, tt.parentPath, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return xerrors.Errorf("file walk error: %w", err)
				}
				if d.IsDir() {
					return nil
				}

				fileInfo, err := d.Info()
				if err != nil {
					t.Fatalf("failed to get file info: %v", err)
				}
				if fileInfo.Mode().Perm()&0111 == 0 {
					return nil
				}
				filePaths = append(filePaths, path)
				return nil
			})
			if err != nil {
				t.Fatalf("failed to walk dir: %v", err)
			}

			sort.Slice(filePaths, func(i, j int) bool { return filePaths[i] < filePaths[j] })
			sort.Slice(tt.expectedFiles, func(i, j int) bool { return tt.expectedFiles[i] < tt.expectedFiles[j] })
			if len(filePaths) != len(tt.expectedFiles) {
				t.Fatalf("length error: actual %d, expected %d", len(filePaths), len(tt.expectedFiles))
			}

			for i := 0; i < len(filePaths); i++ {
				if filePaths[i] != tt.expectedFiles[i] {
					t.Fatalf("%d: actual %s, expected: %s", i, filePaths[i], tt.expectedFiles[i])
				}
			}
		})
	}
}

func TestFileSystemCheckReadDir(t *testing.T) {

	testDirectoryCases := []struct {
		filesystem string
		name       string
		entriesLen int
	}{
		{
			filesystem: "testdata/image.xfs",
			name:       "fmt_extents_block_directories",
			entriesLen: 8,
		},
		{
			filesystem: "testdata/image.xfs",
			name:       "fmt_leaf_directories",
			entriesLen: 200,
		},
		{
			filesystem: "testdata/image.xfs",
			name:       "fmt_local_directory",
			entriesLen: 1,
		},
		{
			filesystem: "testdata/image.xfs",
			name:       "fmt_node_directories",
			entriesLen: 1024,
		},
	}

	for _, tt := range testDirectoryCases {
		t.Run(fmt.Sprintf("test %s read", tt.name), func(t *testing.T) {
			f, err := os.Open(tt.filesystem)
			if err != nil {
				t.Fatal(err)
			}
			info, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}

			fileSystem, err := xfs.NewFS(*io.NewSectionReader(f, 0, info.Size()), nil)
			if err != nil {
				t.Fatal(err)
			}
			dirEntries, err := fileSystem.ReadDir(tt.name)
			if err != nil {
				t.Fatal(err)
			}
			if len(dirEntries) != tt.entriesLen {
				t.Errorf("expected %d, actual %d", len(dirEntries), tt.entriesLen)
			}
		})
	}
}

func TestFileSystemCheckReadFile(t *testing.T) {
	testDirectoryCases := []struct {
		filesystem   string
		name         string
		expectedFile string
	}{
		{
			filesystem:   "testdata/image.xfs",
			name:         "etc/os-release",
			expectedFile: "testdata/os-release",
		},
	}

	for _, tt := range testDirectoryCases {
		t.Run(fmt.Sprintf("test %s read", tt.name), func(t *testing.T) {
			f, err := os.Open(tt.filesystem)
			if err != nil {
				t.Fatal(err)
			}
			info, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}

			fileSystem, err := xfs.NewFS(*io.NewSectionReader(f, 0, info.Size()), nil)
			if err != nil {
				t.Fatal(err)
			}
			file, err := fileSystem.Open(tt.name)
			if err != nil {
				t.Fatalf("failed to open file: %v", err)
			}
			expectedFile, err := os.Open(tt.expectedFile)
			if err != nil {
				t.Fatal(err)
			}

			buf, err := io.ReadAll(file)
			if err != nil {
				t.Fatal(err)
			}
			expectedBuf, err := io.ReadAll(expectedFile)
			if err != nil {
				t.Fatal(err)
			}
			if string(expectedBuf) != string(buf) {
				t.Fatalf("expected %s, actual %s", expectedBuf, buf)
			}
		})
	}
}
