package source

import (
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
