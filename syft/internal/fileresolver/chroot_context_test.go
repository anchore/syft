package fileresolver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ChrootContext_RequestResponse(t *testing.T) {
	// /
	//   somewhere/
	//     outside.txt
	//   root-link -> ./
	//   path/
	//     to/
	//       abs-inside.txt -> /path/to/the/file.txt               # absolute link to somewhere inside of the root
	//       rel-inside.txt -> ./the/file.txt                      # relative link to somewhere inside of the root
	//       the/
	//		   file.txt
	//         abs-outside.txt -> /somewhere/outside.txt           # absolute link to outside of the root
	//         rel-outside -> ../../../somewhere/outside.txt       # relative link to outside of the root
	//

	testDir, err := os.Getwd()
	require.NoError(t, err)
	relative := filepath.Join("test-fixtures", "req-resp")
	absolute := filepath.Join(testDir, relative)

	absPathToTheFile := filepath.Join(absolute, "path", "to", "the", "file.txt")

	absAbsInsidePath := filepath.Join(absolute, "path", "to", "abs-inside.txt")
	absAbsOutsidePath := filepath.Join(absolute, "path", "to", "the", "abs-outside.txt")

	absRelOutsidePath := filepath.Join(absolute, "path", "to", "the", "rel-outside.txt")

	relViaLink := filepath.Join(relative, "root-link")
	absViaLink := filepath.Join(absolute, "root-link")

	absViaLinkPathToTheFile := filepath.Join(absViaLink, "path", "to", "the", "file.txt")
	absViaLinkAbsOutsidePath := filepath.Join(absViaLink, "path", "to", "the", "abs-outside.txt")
	absViaLinkRelOutsidePath := filepath.Join(absViaLink, "path", "to", "the", "rel-outside.txt")

	relViaDoubleLink := filepath.Join(relative, "root-link", "root-link")
	absViaDoubleLink := filepath.Join(absolute, "root-link", "root-link")

	absViaDoubleLinkPathToTheFile := filepath.Join(absViaDoubleLink, "path", "to", "the", "file.txt")
	absViaDoubleLinkRelOutsidePath := filepath.Join(absViaDoubleLink, "path", "to", "the", "rel-outside.txt")

	cleanup := func() {
		_ = os.Remove(absAbsInsidePath)
		_ = os.Remove(absAbsOutsidePath)
	}

	// ensure the absolute symlinks are cleaned up from any previous runs
	cleanup()

	require.NoError(t, os.Symlink(filepath.Join(absolute, "path", "to", "the", "file.txt"), absAbsInsidePath))
	require.NoError(t, os.Symlink(filepath.Join(absolute, "somewhere", "outside.txt"), absAbsOutsidePath))

	t.Cleanup(cleanup)

	cases := []struct {
		name               string
		cwd                string
		root               string
		base               string
		input              string
		expectedNativePath string
		expectedChrootPath string
	}{
		{
			name:               "relative root, relative request, direct",
			root:               relative,
			input:              "path/to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "path/to/the/file.txt",
		},
		{
			name:               "abs root, relative request, direct",
			root:               absolute,
			input:              "path/to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "path/to/the/file.txt",
		},
		{
			name:               "relative root, abs request, direct",
			root:               relative,
			input:              "/path/to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "path/to/the/file.txt",
		},
		{
			name:               "abs root, abs request, direct",
			root:               absolute,
			input:              "/path/to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "path/to/the/file.txt",
		},
		// cwd within root...
		{
			name:               "relative root, relative request, direct, cwd within root",
			cwd:                filepath.Join(relative, "path/to"),
			root:               "../../",
			input:              "path/to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "path/to/the/file.txt",
		},
		{
			name:               "abs root, relative request, direct, cwd within root",
			cwd:                filepath.Join(relative, "path/to"),
			root:               absolute,
			input:              "path/to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "path/to/the/file.txt",
		},
		{
			name:               "relative root, abs request, direct, cwd within root",
			cwd:                filepath.Join(relative, "path/to"),
			root:               "../../",
			input:              "/path/to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "path/to/the/file.txt",
		},
		{
			name: "abs root, abs request, direct, cwd within root",
			cwd:  filepath.Join(relative, "path/to"),

			root:               absolute,
			input:              "/path/to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "path/to/the/file.txt",
		},
		// cwd within symlink root...
		{
			name:               "relative root, relative request, direct, cwd within symlink root",
			cwd:                relViaLink,
			root:               "./",
			input:              "path/to/the/file.txt",
			expectedNativePath: absViaLinkPathToTheFile,
			expectedChrootPath: "path/to/the/file.txt",
		},
		{
			name:               "abs root, relative request, direct, cwd within symlink root",
			cwd:                relViaLink,
			root:               absViaLink,
			input:              "path/to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "path/to/the/file.txt",
		},
		{
			name:               "relative root, abs request, direct, cwd within symlink root",
			cwd:                relViaLink,
			root:               "./",
			input:              "/path/to/the/file.txt",
			expectedNativePath: absViaLinkPathToTheFile,
			expectedChrootPath: "path/to/the/file.txt",
		},
		{
			name:               "abs root, abs request, direct, cwd within symlink root",
			cwd:                relViaLink,
			root:               absViaLink,
			input:              "/path/to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "path/to/the/file.txt",
		},
		// cwd within symlink root, request nested within...
		{
			name:               "relative root, relative nested request, direct, cwd within symlink root",
			cwd:                relViaLink,
			root:               "./path",
			input:              "to/the/file.txt",
			expectedNativePath: absViaLinkPathToTheFile,
			expectedChrootPath: "to/the/file.txt",
		},
		{
			name:               "abs root, relative nested request, direct, cwd within symlink root",
			cwd:                relViaLink,
			root:               filepath.Join(absViaLink, "path"),
			input:              "to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "to/the/file.txt",
		},
		{
			name:               "relative root, abs nested request, direct, cwd within symlink root",
			cwd:                relViaLink,
			root:               "./path",
			input:              "/to/the/file.txt",
			expectedNativePath: absViaLinkPathToTheFile,
			expectedChrootPath: "to/the/file.txt",
		},
		{
			name:               "abs root, abs nested request, direct, cwd within symlink root",
			cwd:                relViaLink,
			root:               filepath.Join(absViaLink, "path"),
			input:              "/to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "to/the/file.txt",
		},
		// cwd within DOUBLE symlink root...
		{
			name:               "relative root, relative request, direct, cwd within (double) symlink root",
			cwd:                relViaDoubleLink,
			root:               "./",
			input:              "path/to/the/file.txt",
			expectedNativePath: absViaDoubleLinkPathToTheFile,
			expectedChrootPath: "path/to/the/file.txt",
		},
		{
			name:               "abs root, relative request, direct, cwd within (double) symlink root",
			cwd:                relViaDoubleLink,
			root:               absViaDoubleLink,
			input:              "path/to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "path/to/the/file.txt",
		},
		{
			name:               "relative root, abs request, direct, cwd within (double) symlink root",
			cwd:                relViaDoubleLink,
			root:               "./",
			input:              "/path/to/the/file.txt",
			expectedNativePath: absViaDoubleLinkPathToTheFile,
			expectedChrootPath: "path/to/the/file.txt",
		},
		{
			name:               "abs root, abs request, direct, cwd within (double) symlink root",
			cwd:                relViaDoubleLink,
			root:               absViaDoubleLink,
			input:              "/path/to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "path/to/the/file.txt",
		},
		// cwd within DOUBLE symlink root, request nested within...
		{
			name:               "relative root, relative nested request, direct, cwd within (double) symlink root",
			cwd:                relViaDoubleLink,
			root:               "./path",
			input:              "to/the/file.txt",
			expectedNativePath: absViaDoubleLinkPathToTheFile,
			expectedChrootPath: "to/the/file.txt",
		},
		{
			name:               "abs root, relative nested request, direct, cwd within (double) symlink root",
			cwd:                relViaDoubleLink,
			root:               filepath.Join(absViaDoubleLink, "path"),
			input:              "to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "to/the/file.txt",
		},
		{
			name:               "relative root, abs nested request, direct, cwd within (double) symlink root",
			cwd:                relViaDoubleLink,
			root:               "./path",
			input:              "/to/the/file.txt",
			expectedNativePath: absViaDoubleLinkPathToTheFile,
			expectedChrootPath: "to/the/file.txt",
		},
		{
			name:               "abs root, abs nested request, direct, cwd within (double) symlink root",
			cwd:                relViaDoubleLink,
			root:               filepath.Join(absViaDoubleLink, "path"),
			input:              "/to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "to/the/file.txt",
		},
		// cwd within DOUBLE symlink root, request nested DEEP within...
		{
			name:               "relative root, relative nested request, direct, cwd deep within (double) symlink root",
			cwd:                filepath.Join(relViaDoubleLink, "path", "to"),
			root:               "../",
			input:              "to/the/file.txt",
			expectedNativePath: absViaDoubleLinkPathToTheFile,
			expectedChrootPath: "to/the/file.txt",
		},
		{
			name:               "abs root, relative nested request, direct, cwd deep within (double) symlink root",
			cwd:                filepath.Join(relViaDoubleLink, "path", "to"),
			root:               filepath.Join(absViaDoubleLink, "path"),
			input:              "to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "to/the/file.txt",
		},
		{
			name:               "relative root, abs nested request, direct, cwd deep within (double) symlink root",
			cwd:                filepath.Join(relViaDoubleLink, "path", "to"),
			root:               "../",
			input:              "/to/the/file.txt",
			expectedNativePath: absViaDoubleLinkPathToTheFile,
			expectedChrootPath: "to/the/file.txt",
		},
		{
			name:               "abs root, abs nested request, direct, cwd deep within (double) symlink root",
			cwd:                filepath.Join(relViaDoubleLink, "path", "to"),
			root:               filepath.Join(absViaDoubleLink, "path"),
			input:              "/to/the/file.txt",
			expectedNativePath: absPathToTheFile,
			expectedChrootPath: "to/the/file.txt",
		},
		// link to outside of root cases...
		{
			name:               "relative root, relative request, abs indirect (outside of root)",
			root:               filepath.Join(relative, "path"),
			input:              "to/the/abs-outside.txt",
			expectedNativePath: absAbsOutsidePath,
			expectedChrootPath: "to/the/abs-outside.txt",
		},
		{
			name:               "abs root, relative request, abs indirect (outside of root)",
			root:               filepath.Join(absolute, "path"),
			input:              "to/the/abs-outside.txt",
			expectedNativePath: absAbsOutsidePath,
			expectedChrootPath: "to/the/abs-outside.txt",
		},
		{
			name:               "relative root, abs request, abs indirect (outside of root)",
			root:               filepath.Join(relative, "path"),
			input:              "/to/the/abs-outside.txt",
			expectedNativePath: absAbsOutsidePath,
			expectedChrootPath: "to/the/abs-outside.txt",
		},
		{
			name:               "abs root, abs request, abs indirect (outside of root)",
			root:               filepath.Join(absolute, "path"),
			input:              "/to/the/abs-outside.txt",
			expectedNativePath: absAbsOutsidePath,
			expectedChrootPath: "to/the/abs-outside.txt",
		},
		{
			name:               "relative root, relative request, relative indirect (outside of root)",
			root:               filepath.Join(relative, "path"),
			input:              "to/the/rel-outside.txt",
			expectedNativePath: absRelOutsidePath,
			expectedChrootPath: "to/the/rel-outside.txt",
		},
		{
			name:               "abs root, relative request, relative indirect (outside of root)",
			root:               filepath.Join(absolute, "path"),
			input:              "to/the/rel-outside.txt",
			expectedNativePath: absRelOutsidePath,
			expectedChrootPath: "to/the/rel-outside.txt",
		},
		{
			name:               "relative root, abs request, relative indirect (outside of root)",
			root:               filepath.Join(relative, "path"),
			input:              "/to/the/rel-outside.txt",
			expectedNativePath: absRelOutsidePath,
			expectedChrootPath: "to/the/rel-outside.txt",
		},
		{
			name:               "abs root, abs request, relative indirect (outside of root)",
			root:               filepath.Join(absolute, "path"),
			input:              "/to/the/rel-outside.txt",
			expectedNativePath: absRelOutsidePath,
			expectedChrootPath: "to/the/rel-outside.txt",
		},
		// link to outside of root cases... cwd within symlink root
		{
			name:               "relative root, relative request, abs indirect (outside of root), cwd within symlink root",
			cwd:                relViaLink,
			root:               "path",
			input:              "to/the/abs-outside.txt",
			expectedNativePath: absViaLinkAbsOutsidePath,
			expectedChrootPath: "to/the/abs-outside.txt",
		},
		{
			name:               "abs root, relative request, abs indirect (outside of root), cwd within symlink root",
			cwd:                relViaLink,
			root:               filepath.Join(absolute, "path"),
			input:              "to/the/abs-outside.txt",
			expectedNativePath: absAbsOutsidePath,
			expectedChrootPath: "to/the/abs-outside.txt",
		},
		{
			name:               "relative root, abs request, abs indirect (outside of root), cwd within symlink root",
			cwd:                relViaLink,
			root:               "path",
			input:              "/to/the/abs-outside.txt",
			expectedNativePath: absViaLinkAbsOutsidePath,
			expectedChrootPath: "to/the/abs-outside.txt",
		},
		{
			name:               "abs root, abs request, abs indirect (outside of root), cwd within symlink root",
			cwd:                relViaLink,
			root:               filepath.Join(absolute, "path"),
			input:              "/to/the/abs-outside.txt",
			expectedNativePath: absAbsOutsidePath,
			expectedChrootPath: "to/the/abs-outside.txt",
		},
		{
			name:               "relative root, relative request, relative indirect (outside of root), cwd within symlink root",
			cwd:                relViaLink,
			root:               "path",
			input:              "to/the/rel-outside.txt",
			expectedNativePath: absViaLinkRelOutsidePath,
			expectedChrootPath: "to/the/rel-outside.txt",
		},
		{
			name:               "abs root, relative request, relative indirect (outside of root), cwd within symlink root",
			cwd:                relViaLink,
			root:               filepath.Join(absolute, "path"),
			input:              "to/the/rel-outside.txt",
			expectedNativePath: absRelOutsidePath,
			expectedChrootPath: "to/the/rel-outside.txt",
		},
		{
			name:               "relative root, abs request, relative indirect (outside of root), cwd within symlink root",
			cwd:                relViaLink,
			root:               "path",
			input:              "/to/the/rel-outside.txt",
			expectedNativePath: absViaLinkRelOutsidePath,
			expectedChrootPath: "to/the/rel-outside.txt",
		},
		{
			name:               "abs root, abs request, relative indirect (outside of root), cwd within symlink root",
			cwd:                relViaLink,
			root:               filepath.Join(absolute, "path"),
			input:              "/to/the/rel-outside.txt",
			expectedNativePath: absRelOutsidePath,
			expectedChrootPath: "to/the/rel-outside.txt",
		},
		{
			name:               "relative root, relative request, relative indirect (outside of root), cwd within DOUBLE symlink root",
			cwd:                relViaDoubleLink,
			root:               "path",
			input:              "to/the/rel-outside.txt",
			expectedNativePath: absViaDoubleLinkRelOutsidePath,
			expectedChrootPath: "to/the/rel-outside.txt",
		},
		{
			name:               "abs root, relative request, relative indirect (outside of root), cwd within DOUBLE symlink root",
			cwd:                relViaDoubleLink,
			root:               filepath.Join(absolute, "path"),
			input:              "to/the/rel-outside.txt",
			expectedNativePath: absRelOutsidePath,
			expectedChrootPath: "to/the/rel-outside.txt",
		},
		{
			name:               "relative root, abs request, relative indirect (outside of root), cwd within DOUBLE symlink root",
			cwd:                relViaDoubleLink,
			root:               "path",
			input:              "/to/the/rel-outside.txt",
			expectedNativePath: absViaDoubleLinkRelOutsidePath,
			expectedChrootPath: "to/the/rel-outside.txt",
		},
		{
			name:               "abs root, abs request, relative indirect (outside of root), cwd within DOUBLE symlink root",
			cwd:                relViaDoubleLink,
			root:               filepath.Join(absolute, "path"),
			input:              "/to/the/rel-outside.txt",
			expectedNativePath: absRelOutsidePath,
			expectedChrootPath: "to/the/rel-outside.txt",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {

			// we need to mimic a shell, otherwise we won't get a path within a symlink
			targetPath := filepath.Join(testDir, c.cwd)
			t.Setenv("PWD", filepath.Clean(targetPath))

			require.NoError(t, err)
			require.NoError(t, os.Chdir(targetPath))
			t.Cleanup(func() {
				require.NoError(t, os.Chdir(testDir))
			})

			chroot, err := NewChrootContextFromCWD(c.root, c.base)
			require.NoError(t, err)
			require.NotNil(t, chroot)

			req, err := chroot.ToNativePath(c.input)
			require.NoError(t, err)
			assert.Equal(t, c.expectedNativePath, req, "native path different")

			resp := chroot.ToChrootPath(req)
			assert.Equal(t, c.expectedChrootPath, resp, "chroot path different")
		})
	}
}

func TestToNativeGlob(t *testing.T) {
	tests := []struct {
		name           string
		chrootContext  ChrootContext
		chrootPath     string
		expectedResult string
		expectedError  error
	}{
		{
			name: "ignore empty path",
			chrootContext: ChrootContext{
				root:              "/root",
				cwdRelativeToRoot: "/cwd",
			},
			chrootPath:     "",
			expectedResult: "",
			expectedError:  nil,
		},
		{
			name: "ignore if just a path",
			chrootContext: ChrootContext{
				root:              "/root",
				cwdRelativeToRoot: "/cwd",
			},
			chrootPath:     "/some/path/file.txt",
			expectedResult: "/root/some/path/file.txt",
			expectedError:  nil,
		},
		{
			name: "ignore starting with glob",
			chrootContext: ChrootContext{
				root:              "/root",
				cwdRelativeToRoot: "/cwd",
			},
			chrootPath:     "*/relative/path/*",
			expectedResult: "*/relative/path/*",
			expectedError:  nil,
		},
		{
			name: "absolute path with glob",
			chrootContext: ChrootContext{
				root:              "/root",
				cwdRelativeToRoot: "/cwd",
			},
			chrootPath:     "/some/path/*",
			expectedResult: "/root/some/path/*",
			expectedError:  nil,
		},
		{
			name: "relative path with glob",
			chrootContext: ChrootContext{
				root:              "/root",
				cwdRelativeToRoot: "/cwd",
			},
			chrootPath:     "relative/path/*",
			expectedResult: "/cwd/relative/path/*",
			expectedError:  nil,
		},
		{
			name: "relative path with no root",
			chrootContext: ChrootContext{
				root:              "",
				cwdRelativeToRoot: "/cwd",
			},
			chrootPath:     "relative/path/*",
			expectedResult: "/cwd/relative/path/*",
			expectedError:  nil,
		},
		{
			name: "globs everywhere",
			chrootContext: ChrootContext{
				root:              "/root",
				cwdRelativeToRoot: "/cwd",
			},
			chrootPath:     "relative/path/**/file*.txt",
			expectedResult: "/cwd/relative/path/**/file*.txt",
			expectedError:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.chrootContext.ToNativeGlob(tt.chrootPath)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}
