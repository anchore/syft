package source

import (
	"github.com/stretchr/testify/require"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/stereoscope/pkg/imagetest"
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

			resolver, err := newAllLayersResolver(img)
			if err != nil {
				t.Fatalf("could not create resolver: %+v", err)
			}

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
			if err != nil {
				t.Fatalf("could not use resolver: %+v", err)
			}

			if len(refs) != len(c.resolutions) {
				t.Fatalf("unexpected number of resolutions: %d", len(refs))
			}

			for idx, actual := range refs {
				expected := c.resolutions[idx]

				if string(actual.ref.RealPath) != expected.path {
					t.Errorf("bad resolve path: '%s'!='%s'", string(actual.ref.RealPath), expected.path)
				}

				if expected.path != "" && string(actual.ref.RealPath) != actual.RealPath {
					t.Errorf("we should always prefer real paths over ones with links")
				}

				entry, err := img.FileCatalog.Get(actual.ref)
				if err != nil {
					t.Fatalf("failed to get metadata: %+v", err)
				}

				if entry.Layer.Metadata.Index != expected.layer {
					t.Errorf("bad resolve layer: '%d'!='%d'", entry.Layer.Metadata.Index, expected.layer)
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

			resolver, err := newAllLayersResolver(img)
			if err != nil {
				t.Fatalf("could not create resolver: %+v", err)
			}

			refs, err := resolver.FilesByGlob(c.glob)
			if err != nil {
				t.Fatalf("could not use resolver: %+v", err)
			}

			if len(refs) != len(c.resolutions) {
				t.Fatalf("unexpected number of resolutions: %d", len(refs))
			}

			for idx, actual := range refs {
				expected := c.resolutions[idx]

				if string(actual.ref.RealPath) != expected.path {
					t.Errorf("bad resolve path: '%s'!='%s'", string(actual.ref.RealPath), expected.path)
				}

				if expected.path != "" && string(actual.ref.RealPath) != actual.RealPath {
					t.Errorf("we should always prefer real paths over ones with links")
				}

				entry, err := img.FileCatalog.Get(actual.ref)
				if err != nil {
					t.Fatalf("failed to get metadata: %+v", err)
				}

				if entry.Layer.Metadata.Index != expected.layer {
					t.Errorf("bad resolve layer: '%d'!='%d'", entry.Layer.Metadata.Index, expected.layer)
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

			resolver, err := newAllLayersResolver(img)
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

	resolver, err := newAllLayersResolver(img)
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

			resolver, err := newAllLayersResolver(img)
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

func Test_imageAllLayersResolver_resolvesLinks(t *testing.T) {
	tests := []struct {
		name     string
		runner   func(FileResolver) []Location
		expected []Location
	}{
		{
			name: "by mimetype",
			runner: func(resolver FileResolver) []Location {
				// links should not show up when searching mimetype
				actualLocations, err := resolver.FilesByMIMEType("text/plain")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				{
					Coordinates: Coordinates{
						RealPath: "/etc/group",
					},
					VirtualPath: "/etc/group",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/etc/passwd",
					},
					VirtualPath: "/etc/passwd",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/etc/shadow",
					},
					VirtualPath: "/etc/shadow",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/file-1.txt",
					},
					VirtualPath: "/file-1.txt",
				},
				// copy 1
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/file-2.txt",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/file-3.txt",
					},
					VirtualPath: "/file-3.txt",
				},
				// copy 2
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/file-2.txt",
				},
				// copy 1
				{
					Coordinates: Coordinates{
						RealPath: "/parent/file-4.txt",
					},
					VirtualPath: "/parent/file-4.txt",
				},
				// copy 2
				{
					Coordinates: Coordinates{
						RealPath: "/parent/file-4.txt",
					},
					VirtualPath: "/parent/file-4.txt",
				},
			},
		},
		{
			name: "by glob",
			runner: func(resolver FileResolver) []Location {
				// links are searched, but resolve to the real files
				actualLocations, err := resolver.FilesByGlob("*ink-*")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				{
					Coordinates: Coordinates{
						RealPath: "/file-1.txt",
					},
					VirtualPath: "/link-1",
				},
				// copy 1
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/link-2",
				},
				// copy 2
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/link-2",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/file-3.txt",
					},
					VirtualPath: "/link-within",
				},
			},
		},
		{
			name: "by path to degree 1 link",
			runner: func(resolver FileResolver) []Location {
				// links resolve to the final file
				actualLocations, err := resolver.FilesByPath("/link-2")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				// we have multiple copies across layers
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/link-2",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/link-2",
				},
			},
		},
		{
			name: "by path to degree 2 link",
			runner: func(resolver FileResolver) []Location {
				// multiple links resolves to the final file
				actualLocations, err := resolver.FilesByPath("/link-indirect")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				// we have multiple copies across layers
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/link-indirect",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/link-indirect",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

			resolver, err := newAllLayersResolver(img)
			assert.NoError(t, err)

			actualLocations := test.runner(resolver)
			assert.Len(t, actualLocations, len(test.expected))
			for i, actual := range actualLocations {
				assert.Equal(t, test.expected[i].RealPath, actual.RealPath)
				assert.Equal(t, test.expected[i].VirtualPath, actual.VirtualPath)
			}
		})
	}

}
