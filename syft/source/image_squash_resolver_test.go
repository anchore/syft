package source

import (
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/stereoscope/pkg/imagetest"
)

func TestImageSquashResolver_FilesByPath(t *testing.T) {
	cases := []struct {
		name                 string
		linkPath             string
		resolveLayer         uint
		resolvePath          string
		forcePositiveHasPath bool
	}{
		{
			name:         "link with previous data",
			linkPath:     "/link-1",
			resolveLayer: 1,
			resolvePath:  "/file-1.txt",
		},
		{
			name:         "link with in layer data",
			linkPath:     "/link-within",
			resolveLayer: 5,
			resolvePath:  "/file-3.txt",
		},
		{
			name:         "link with overridden data",
			linkPath:     "/link-2",
			resolveLayer: 7,
			resolvePath:  "/file-2.txt",
		},
		{
			name:         "indirect link (with overridden data)",
			linkPath:     "/link-indirect",
			resolveLayer: 7,
			resolvePath:  "/file-2.txt",
		},
		{
			name:         "dead link",
			linkPath:     "/link-dead",
			resolveLayer: 8,
			resolvePath:  "",
			// the path should exist, even if the link is dead
			forcePositiveHasPath: true,
		},
		{
			name:        "ignore directories",
			linkPath:    "/bin",
			resolvePath: "",
			// the path should exist, even if we ignore it
			forcePositiveHasPath: true,
		},
		{
			name:         "parent is a link (with overridden data)",
			linkPath:     "/parent-link/file-4.txt",
			resolveLayer: 11,
			resolvePath:  "/parent/file-4.txt",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

			resolver, err := newImageSquashResolver(img)
			if err != nil {
				t.Fatalf("could not create resolver: %+v", err)
			}

			hasPath := resolver.HasPath(c.linkPath)
			if !c.forcePositiveHasPath {
				if c.resolvePath != "" && !hasPath {
					t.Errorf("expected HasPath() to indicate existance, but did not")
				} else if c.resolvePath == "" && hasPath {
					t.Errorf("expeced HasPath() to NOT indicate existance, but does")
				}
			} else if !hasPath {
				t.Errorf("expected HasPath() to indicate existance, but did not (force path)")
			}

			refs, err := resolver.FilesByPath(c.linkPath)
			if err != nil {
				t.Fatalf("could not use resolver: %+v", err)
			}

			expectedRefs := 1
			if c.resolvePath == "" {
				expectedRefs = 0
			}

			if len(refs) != expectedRefs {
				t.Fatalf("unexpected number of resolutions: %d", len(refs))
			}

			if expectedRefs == 0 {
				// nothing else to assert
				return
			}

			actual := refs[0]

			if string(actual.ref.RealPath) != c.resolvePath {
				t.Errorf("bad resolve path: '%s'!='%s'", string(actual.ref.RealPath), c.resolvePath)
			}

			if c.resolvePath != "" && string(actual.ref.RealPath) != actual.RealPath {
				t.Errorf("we should always prefer real paths over ones with links")
			}

			entry, err := img.FileCatalog.Get(actual.ref)
			if err != nil {
				t.Fatalf("failed to get metadata: %+v", err)
			}

			if entry.Layer.Metadata.Index != c.resolveLayer {
				t.Errorf("bad resolve layer: '%d'!='%d'", entry.Layer.Metadata.Index, c.resolveLayer)
			}
		})
	}
}

func TestImageSquashResolver_FilesByGlob(t *testing.T) {
	cases := []struct {
		name         string
		glob         string
		resolveLayer uint
		resolvePath  string
	}{
		{
			name:         "link with previous data",
			glob:         "**/link-1",
			resolveLayer: 1,
			resolvePath:  "/file-1.txt",
		},
		{
			name:         "link with in layer data",
			glob:         "**/link-within",
			resolveLayer: 5,
			resolvePath:  "/file-3.txt",
		},
		{
			name:         "link with overridden data",
			glob:         "**/link-2",
			resolveLayer: 7,
			resolvePath:  "/file-2.txt",
		},
		{
			name:         "indirect link (with overridden data)",
			glob:         "**/link-indirect",
			resolveLayer: 7,
			resolvePath:  "/file-2.txt",
		},
		{
			name: "dead link",
			glob: "**/link-dead",
			// dead links are dead! they shouldn't match on globs
			resolvePath: "",
		},
		{
			name:        "ignore directories",
			glob:        "**/bin",
			resolvePath: "",
		},
		{
			name:         "parent without link",
			glob:         "**/parent/*.txt",
			resolveLayer: 11,
			resolvePath:  "/parent/file-4.txt",
		},
		{
			name:         "parent is a link (override)",
			glob:         "**/parent-link/file-4.txt",
			resolveLayer: 11,
			resolvePath:  "/parent/file-4.txt",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

			resolver, err := newImageSquashResolver(img)
			if err != nil {
				t.Fatalf("could not create resolver: %+v", err)
			}

			refs, err := resolver.FilesByGlob(c.glob)
			if err != nil {
				t.Fatalf("could not use resolver: %+v", err)
			}

			expectedRefs := 1
			if c.resolvePath == "" {
				expectedRefs = 0
			}

			if len(refs) != expectedRefs {
				t.Fatalf("unexpected number of resolutions: %d", len(refs))
			}

			if expectedRefs == 0 {
				// nothing else to assert
				return
			}

			actual := refs[0]

			if string(actual.ref.RealPath) != c.resolvePath {
				t.Errorf("bad resolve path: '%s'!='%s'", string(actual.ref.RealPath), c.resolvePath)
			}

			if c.resolvePath != "" && string(actual.ref.RealPath) != actual.RealPath {
				t.Errorf("we should always prefer real paths over ones with links")
			}

			entry, err := img.FileCatalog.Get(actual.ref)
			if err != nil {
				t.Fatalf("failed to get metadata: %+v", err)
			}

			if entry.Layer.Metadata.Index != c.resolveLayer {
				t.Errorf("bad resolve layer: '%d'!='%d'", entry.Layer.Metadata.Index, c.resolveLayer)
			}
		})
	}
}

func Test_imageSquashResolver_FilesByMIMEType(t *testing.T) {

	tests := []struct {
		fixtureName   string
		mimeType      string
		expectedPaths *strset.Set
	}{
		{
			fixtureName:   "image-simple",
			mimeType:      "text/plain",
			expectedPaths: strset.New("/somefile-1.txt", "/somefile-2.txt", "/really/nested/file-3.txt"),
		},
	}
	for _, test := range tests {
		t.Run(test.fixtureName, func(t *testing.T) {
			img := imagetest.GetFixtureImage(t, "docker-archive", test.fixtureName)

			resolver, err := newImageSquashResolver(img)
			assert.NoError(t, err)

			locations, err := resolver.FilesByMIMEType(test.mimeType)
			assert.NoError(t, err)

			assert.Equal(t, test.expectedPaths.Size(), len(locations))
			for _, l := range locations {
				assert.True(t, test.expectedPaths.Has(l.RealPath), "does not have path %q", l.RealPath)
			}
		})
	}
}

func Test_imageSquashResolver_hasFilesystemIDInLocation(t *testing.T) {
	img := imagetest.GetFixtureImage(t, "docker-archive", "image-duplicate-path")

	resolver, err := newImageSquashResolver(img)
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
