package fileresolver

import (
	"context"
	"io"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/file"
)

type resolution struct {
	layer uint
	path  string
}

func TestAllLayersResolver_FilesByPath(t *testing.T) {
	cases := []struct {
		name                 string
		linkPath             string
		resolutions          []resolution
		forcePositiveHasPath bool
	}{
		{
			name:     "link with previous data",
			linkPath: "/link-1",
			resolutions: []resolution{
				{
					layer: 1,
					path:  "/file-1.txt",
				},
			},
		},
		{
			name:     "link with in layer data",
			linkPath: "/link-within",
			resolutions: []resolution{
				{
					layer: 5,
					path:  "/file-3.txt",
				},
			},
		},
		{
			name:     "link with overridden data",
			linkPath: "/link-2",
			resolutions: []resolution{
				{
					layer: 4,
					path:  "/file-2.txt",
				},
				{
					layer: 7,
					path:  "/file-2.txt",
				},
			},
		},
		{
			name:     "indirect link (with overridden data)",
			linkPath: "/link-indirect",
			resolutions: []resolution{
				{
					layer: 4,
					path:  "/file-2.txt",
				},
				{
					layer: 7,
					path:  "/file-2.txt",
				},
			},
		},
		{
			name:                 "dead link",
			linkPath:             "/link-dead",
			resolutions:          []resolution{},
			forcePositiveHasPath: true,
		},
		{
			name:        "ignore directories",
			linkPath:    "/bin",
			resolutions: []resolution{},
			// directories don't resolve BUT do exist
			forcePositiveHasPath: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

			resolver, err := NewFromContainerImageAllLayers(img)
			require.NoError(t, err)

			hasPath := resolver.HasPath(c.linkPath)
			if !c.forcePositiveHasPath {
				if len(c.resolutions) > 0 && !hasPath {
					t.Errorf("expected HasPath() to indicate existance, but did not")
				} else if len(c.resolutions) == 0 && hasPath {
					t.Errorf("expeced HasPath() to NOT indicate existance, but does")
				}
			} else if !hasPath {
				t.Errorf("expected HasPath() to indicate existance, but did not (force path)")
			}

			refs, err := resolver.FilesByPath(c.linkPath)
			require.NoError(t, err)

			if len(refs) != len(c.resolutions) {
				t.Fatalf("unexpected number of resolutions: %d", len(refs))
			}

			for idx, actual := range refs {
				expected := c.resolutions[idx]

				if string(actual.Reference().RealPath) != expected.path {
					t.Errorf("bad resolve path: '%s'!='%s'", string(actual.Reference().RealPath), expected.path)
				}

				if expected.path != "" && string(actual.Reference().RealPath) != actual.RealPath {
					t.Errorf("we should always prefer real paths over ones with links")
				}

				layer := img.FileCatalog.Layer(actual.Reference())
				if layer.Metadata.Index != expected.layer {
					t.Errorf("bad resolve layer: '%d'!='%d'", layer.Metadata.Index, expected.layer)
				}
			}
		})
	}
}

func TestAllLayersResolver_FilesByGlob(t *testing.T) {
	cases := []struct {
		name        string
		glob        string
		resolutions []resolution
	}{
		{
			name: "link with previous data",
			glob: "**/*ink-1",
			resolutions: []resolution{
				{
					layer: 1,
					path:  "/file-1.txt",
				},
			},
		},
		{
			name: "link with in layer data",
			glob: "**/*nk-within",
			resolutions: []resolution{
				{
					layer: 5,
					path:  "/file-3.txt",
				},
			},
		},
		{
			name: "link with overridden data",
			glob: "**/*ink-2",
			resolutions: []resolution{
				{
					layer: 4,
					path:  "/file-2.txt",
				},
				{
					layer: 7,
					path:  "/file-2.txt",
				},
			},
		},
		{
			name: "indirect link (with overridden data)",
			glob: "**/*nk-indirect",
			resolutions: []resolution{
				{
					layer: 4,
					path:  "/file-2.txt",
				},
				{
					layer: 7,
					path:  "/file-2.txt",
				},
			},
		},
		{
			name:        "dead link",
			glob:        "**/*k-dead",
			resolutions: []resolution{},
		},
		{
			name:        "ignore directories",
			glob:        "**/bin",
			resolutions: []resolution{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

			resolver, err := NewFromContainerImageAllLayers(img)
			require.NoError(t, err)

			refs, err := resolver.FilesByGlob(c.glob)
			require.NoError(t, err)

			if len(refs) != len(c.resolutions) {
				t.Fatalf("unexpected number of resolutions: %d", len(refs))
			}

			for idx, actual := range refs {
				expected := c.resolutions[idx]

				if string(actual.Reference().RealPath) != expected.path {
					t.Errorf("bad resolve path: '%s'!='%s'", string(actual.Reference().RealPath), expected.path)
				}

				if expected.path != "" && string(actual.Reference().RealPath) != actual.RealPath {
					t.Errorf("we should always prefer real paths over ones with links")
				}

				layer := img.FileCatalog.Layer(actual.Reference())

				if layer.Metadata.Index != expected.layer {
					t.Errorf("bad resolve layer: '%d'!='%d'", layer.Metadata.Index, expected.layer)
				}
			}
		})
	}
}

func Test_imageAllLayersResolver_FilesByMIMEType(t *testing.T) {

	tests := []struct {
		fixtureName   string
		mimeType      string
		expectedPaths []string
	}{
		{
			fixtureName:   "image-duplicate-path",
			mimeType:      "text/plain",
			expectedPaths: []string{"/somefile-1.txt", "/somefile-1.txt"},
		},
	}
	for _, test := range tests {
		t.Run(test.fixtureName, func(t *testing.T) {
			img := imagetest.GetFixtureImage(t, "docker-archive", test.fixtureName)

			resolver, err := NewFromContainerImageAllLayers(img)
			assert.NoError(t, err)

			locations, err := resolver.FilesByMIMEType(test.mimeType)
			assert.NoError(t, err)

			assert.Len(t, test.expectedPaths, len(locations))
			for idx, l := range locations {
				assert.Equal(t, test.expectedPaths[idx], l.RealPath, "does not have path %q", l.RealPath)
			}
		})
	}
}

func Test_imageAllLayersResolver_hasFilesystemIDInLocation(t *testing.T) {
	img := imagetest.GetFixtureImage(t, "docker-archive", "image-duplicate-path")

	resolver, err := NewFromContainerImageAllLayers(img)
	assert.NoError(t, err)

	locations, err := resolver.FilesByMIMEType("text/plain")
	assert.NoError(t, err)
	assert.NotEmpty(t, locations)
	for _, location := range locations {
		assert.NotEmpty(t, location.FileSystemID)
	}

	locations, err = resolver.FilesByGlob("*.txt")
	assert.NoError(t, err)
	assert.NotEmpty(t, locations)
	for _, location := range locations {
		assert.NotEmpty(t, location.FileSystemID)
	}

	locations, err = resolver.FilesByPath("/somefile-1.txt")
	assert.NoError(t, err)
	assert.NotEmpty(t, locations)
	for _, location := range locations {
		assert.NotEmpty(t, location.FileSystemID)
	}

}

func TestAllLayersImageResolver_FilesContents(t *testing.T) {

	tests := []struct {
		name     string
		fixture  string
		contents []string
	}{
		{
			name:    "one degree",
			fixture: "link-2",
			contents: []string{
				"file 2!",            // from the first resolved layer's perspective
				"NEW file override!", // from the second resolved layers perspective
			},
		},
		{
			name:    "two degrees",
			fixture: "link-indirect",
			contents: []string{
				"file 2!",
				"NEW file override!",
			},
		},
		{
			name:     "dead link",
			fixture:  "link-dead",
			contents: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

			resolver, err := NewFromContainerImageAllLayers(img)
			assert.NoError(t, err)

			refs, err := resolver.FilesByPath(test.fixture)
			require.NoError(t, err)

			// the given path should have an overridden file
			require.Len(t, refs, len(test.contents))

			for idx, loc := range refs {
				reader, err := resolver.FileContentsByLocation(loc)
				require.NoError(t, err)

				actual, err := io.ReadAll(reader)
				require.NoError(t, err)

				assert.Equal(t, test.contents[idx], string(actual))
			}

		})
	}
}

func TestAllLayersImageResolver_FilesContents_errorOnDirRequest(t *testing.T) {

	img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

	resolver, err := NewFromContainerImageAllLayers(img)
	assert.NoError(t, err)

	var dirLoc *file.Location
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for loc := range resolver.AllLocations(ctx) {
		entry, err := resolver.img.FileCatalog.Get(loc.Reference())
		require.NoError(t, err)
		if entry.Metadata.IsDir() {
			dirLoc = &loc
			break
		}
	}

	require.NotNil(t, dirLoc)

	reader, err := resolver.FileContentsByLocation(*dirLoc)
	require.Error(t, err)
	require.Nil(t, reader)
}

func Test_imageAllLayersResolver_resolvesLinks(t *testing.T) {
	tests := []struct {
		name     string
		runner   func(file.Resolver) []file.Location
		expected []file.Location
	}{
		{
			name: "by mimetype",
			runner: func(resolver file.Resolver) []file.Location {
				// links should not show up when searching mimetype
				actualLocations, err := resolver.FilesByMIMEType("text/plain")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []file.Location{
				file.NewVirtualLocation("/etc/group", "/etc/group"),
				file.NewVirtualLocation("/etc/passwd", "/etc/passwd"),
				file.NewVirtualLocation("/etc/shadow", "/etc/shadow"),
				file.NewVirtualLocation("/file-1.txt", "/file-1.txt"),
				file.NewVirtualLocation("/file-2.txt", "/file-2.txt"), // copy 1
				// note: we're de-duping the redundant access to file-3.txt
				// ... (there would usually be two copies)
				file.NewVirtualLocation("/file-3.txt", "/file-3.txt"),
				file.NewVirtualLocation("/file-2.txt", "/file-2.txt"),               // copy 2
				file.NewVirtualLocation("/parent/file-4.txt", "/parent/file-4.txt"), // copy 1
				file.NewVirtualLocation("/parent/file-4.txt", "/parent/file-4.txt"), // copy 2
			},
		},
		{
			name: "by glob to links",
			runner: func(resolver file.Resolver) []file.Location {
				// links are searched, but resolve to the real files
				actualLocations, err := resolver.FilesByGlob("*ink-*")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []file.Location{
				file.NewVirtualLocation("/file-1.txt", "/link-1"),
				file.NewVirtualLocation("/file-2.txt", "/link-2"), // copy 1
				file.NewVirtualLocation("/file-2.txt", "/link-2"), // copy 2
				file.NewVirtualLocation("/file-3.txt", "/link-within"),
			},
		},
		{
			name: "by basename",
			runner: func(resolver file.Resolver) []file.Location {
				// links are searched, but resolve to the real files
				actualLocations, err := resolver.FilesByGlob("**/file-2.txt")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []file.Location{
				file.NewVirtualLocation("/file-2.txt", "/file-2.txt"), // copy 1
				file.NewVirtualLocation("/file-2.txt", "/file-2.txt"), // copy 2
			},
		},
		{
			name: "by basename glob",
			runner: func(resolver file.Resolver) []file.Location {
				// links are searched, but resolve to the real files
				actualLocations, err := resolver.FilesByGlob("**/file-?.txt")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []file.Location{
				file.NewVirtualLocation("/file-1.txt", "/file-1.txt"),
				file.NewVirtualLocation("/file-2.txt", "/file-2.txt"), // copy 1
				file.NewVirtualLocation("/file-2.txt", "/file-2.txt"), // copy 2
				file.NewVirtualLocation("/file-3.txt", "/file-3.txt"),
				file.NewVirtualLocation("/parent/file-4.txt", "/parent/file-4.txt"),
				file.NewVirtualLocation("/parent/file-4.txt", "/parent/file-4.txt"), // when we copy into the link path, the same file-4.txt is copied
			},
		},
		{
			name: "by extension",
			runner: func(resolver file.Resolver) []file.Location {
				// links are searched, but resolve to the real files
				actualLocations, err := resolver.FilesByGlob("**/*.txt")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []file.Location{
				file.NewVirtualLocation("/file-1.txt", "/file-1.txt"),
				file.NewVirtualLocation("/file-2.txt", "/file-2.txt"), // copy 1
				file.NewVirtualLocation("/file-2.txt", "/file-2.txt"), // copy 2
				file.NewVirtualLocation("/file-3.txt", "/file-3.txt"),
				file.NewVirtualLocation("/parent/file-4.txt", "/parent/file-4.txt"),
				file.NewVirtualLocation("/parent/file-4.txt", "/parent/file-4.txt"), // when we copy into the link path, the same file-4.txt is copied
			},
		},
		{
			name: "by path to degree 1 link",
			runner: func(resolver file.Resolver) []file.Location {
				// links resolve to the final file
				actualLocations, err := resolver.FilesByPath("/link-2")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []file.Location{
				// we have multiple copies across layers
				file.NewVirtualLocation("/file-2.txt", "/link-2"),
				file.NewVirtualLocation("/file-2.txt", "/link-2"),
			},
		},
		{
			name: "by path to degree 2 link",
			runner: func(resolver file.Resolver) []file.Location {
				// multiple links resolves to the final file
				actualLocations, err := resolver.FilesByPath("/link-indirect")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []file.Location{
				// we have multiple copies across layers
				file.NewVirtualLocation("/file-2.txt", "/link-indirect"),
				file.NewVirtualLocation("/file-2.txt", "/link-indirect"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

			resolver, err := NewFromContainerImageAllLayers(img)
			assert.NoError(t, err)

			actual := test.runner(resolver)

			compareLocations(t, test.expected, actual)
		})
	}

}

func TestAllLayersResolver_AllLocations(t *testing.T) {
	img := imagetest.GetFixtureImage(t, "docker-archive", "image-files-deleted")

	resolver, err := NewFromContainerImageAllLayers(img)
	assert.NoError(t, err)

	paths := strset.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for loc := range resolver.AllLocations(ctx) {
		paths.Add(loc.RealPath)
	}
	expected := []string{
		"/Dockerfile",
		"/file-1.txt",
		"/file-3.txt",
		"/target",
		"/target/file-2.txt",

		"/.wh.bin",
		"/.wh.file-1.txt",
		"/.wh.lib",
		"/bin",
		"/bin/arch",
		"/bin/ash",
		"/bin/base64",
		"/bin/bbconfig",
		"/bin/busybox",
		"/bin/cat",
		"/bin/chattr",
		"/bin/chgrp",
		"/bin/chmod",
		"/bin/chown",
		"/bin/cp",
		"/bin/date",
		"/bin/dd",
		"/bin/df",
		"/bin/dmesg",
		"/bin/dnsdomainname",
		"/bin/dumpkmap",
		"/bin/echo",
		"/bin/ed",
		"/bin/egrep",
		"/bin/false",
		"/bin/fatattr",
		"/bin/fdflush",
		"/bin/fgrep",
		"/bin/fsync",
		"/bin/getopt",
		"/bin/grep",
		"/bin/gunzip",
		"/bin/gzip",
		"/bin/hostname",
		"/bin/ionice",
		"/bin/iostat",
		"/bin/ipcalc",
		"/bin/kbd_mode",
		"/bin/kill",
		"/bin/link",
		"/bin/linux32",
		"/bin/linux64",
		"/bin/ln",
		"/bin/login",
		"/bin/ls",
		"/bin/lsattr",
		"/bin/lzop",
		"/bin/makemime",
		"/bin/mkdir",
		"/bin/mknod",
		"/bin/mktemp",
		"/bin/more",
		"/bin/mount",
		"/bin/mountpoint",
		"/bin/mpstat",
		"/bin/mv",
		"/bin/netstat",
		"/bin/nice",
		"/bin/pidof",
		"/bin/ping",
		"/bin/ping6",
		"/bin/pipe_progress",
		"/bin/printenv",
		"/bin/ps",
		"/bin/pwd",
		"/bin/reformime",
		"/bin/rev",
		"/bin/rm",
		"/bin/rmdir",
		"/bin/run-parts",
		"/bin/sed",
		"/bin/setpriv",
		"/bin/setserial",
		"/bin/sh",
		"/bin/sleep",
		"/bin/stat",
		"/bin/stty",
		"/bin/su",
		"/bin/sync",
		"/bin/tar",
		"/bin/touch",
		"/bin/true",
		"/bin/umount",
		"/bin/uname",
		"/bin/usleep",
		"/bin/watch",
		"/bin/zcat",
		"/lib",
		"/lib/apk",
		"/lib/apk/db",
		"/lib/apk/db/installed",
		"/lib/apk/db/lock",
		"/lib/apk/db/scripts.tar",
		"/lib/apk/db/triggers",
		"/lib/apk/exec",
		"/lib/firmware",
		"/lib/ld-musl-x86_64.so.1",
		"/lib/libapk.so.3.12.0",
		"/lib/libc.musl-x86_64.so.1",
		"/lib/libcrypto.so.3",
		"/lib/libssl.so.3",
		"/lib/libz.so.1",
		"/lib/libz.so.1.2.13",
		"/lib/mdev",
		"/lib/modules-load.d",
		"/lib/sysctl.d",
		"/lib/sysctl.d/00-alpine.conf",
	}

	// depending on how the image is built (either from linux or mac), sys and proc might accidentally be added to the image.
	// this isn't important for the test, so we remove them.
	paths.Remove("/proc", "/sys", "/dev", "/etc")

	// Remove cache created by Mac Rosetta when emulating different arches
	paths.Remove("/.cache/rosetta", "/.cache")

	pathsList := paths.List()
	sort.Strings(pathsList)

	assert.ElementsMatchf(t, expected, pathsList, "expected all paths to be indexed, but found different paths: \n%s", cmp.Diff(expected, paths.List()))
}
