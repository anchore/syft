package source

import (
	"testing"

	"github.com/anchore/stereoscope/pkg/imagetest"
)

type resolution struct {
	layer uint
	path  string
}

func TestAllLayersResolver_FilesByPath(t *testing.T) {
	cases := []struct {
		name        string
		linkPath    string
		resolutions []resolution
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
					layer: 3,
					path:  "/link-2",
				},
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
			name:     "dead link",
			linkPath: "/link-dead",
			resolutions: []resolution{
				{
					layer: 8,
					path:  "/link-dead",
				},
			},
		},
		{
			name:        "ignore directories",
			linkPath:    "/bin",
			resolutions: []resolution{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			img, cleanup := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")
			defer cleanup()

			resolver, err := NewAllLayersResolver(img)
			if err != nil {
				t.Fatalf("could not create resolver: %+v", err)
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

				if actual.Path != expected.path {
					t.Errorf("bad resolve path: '%s'!='%s'", actual.Path, expected.path)
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
					layer: 3,
					path:  "/link-2",
				},
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
			name: "dead link",
			glob: "**/*k-dead",
			resolutions: []resolution{
				{
					layer: 8,
					path:  "/link-dead",
				},
			},
		},
		{
			name:        "ignore directories",
			glob:        "**/bin",
			resolutions: []resolution{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			img, cleanup := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")
			defer cleanup()

			resolver, err := NewAllLayersResolver(img)
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

				if actual.Path != expected.path {
					t.Errorf("bad resolve path: '%s'!='%s'", actual.Path, expected.path)
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
