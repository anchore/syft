package fileresolver

import (
	"context"
	"fmt"
	"io"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/file"
)

type mockSimpleResolver struct {
	file.Resolver // embed to fulfill the interface, panics for stuff not implemented
	paths         *strset.Set
	locations     map[string][]file.Location
}

func newMockSimpleResolver(locations []file.Location) *mockSimpleResolver {
	paths := strset.New()
	locationMap := make(map[string][]file.Location)
	for _, loc := range locations {
		paths.Add(loc.RealPath)
		paths.Add(loc.AccessPath)
		locationMap[loc.RealPath] = append(locationMap[loc.RealPath], loc)
	}
	return &mockSimpleResolver{
		paths:     paths,
		locations: locationMap,
	}
}

func (m *mockSimpleResolver) HasPath(p string) bool {
	return m.paths.Has(p)
}

func (m *mockSimpleResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	var results []file.Location
	for _, path := range paths {
		if locs, exists := m.locations[path]; exists {
			results = append(results, locs...)
		}
	}
	return results, nil
}

func Test_ContainerImageDeepSquash_FilesByPath(t *testing.T) {
	cases := []struct {
		name                 string
		linkPath             string
		resolveLayer         uint
		resolvePath          string
		forcePositiveHasPath bool
		expectedRefs         int
	}{
		{
			name:         "link with previous data",
			linkPath:     "/link-1",
			resolveLayer: 1,
			resolvePath:  "/file-1.txt",
			expectedRefs: 1,
		},
		{
			name:         "link with in layer data",
			linkPath:     "/link-within",
			resolveLayer: 5,
			resolvePath:  "/file-3.txt",
			expectedRefs: 1,
		},
		{
			name:         "link with overridden data",
			linkPath:     "/link-2",
			resolveLayer: 7,
			resolvePath:  "/file-2.txt",
			expectedRefs: 2,
		},
		{
			name:         "indirect link (with overridden data)",
			linkPath:     "/link-indirect",
			resolveLayer: 7,
			resolvePath:  "/file-2.txt",
			expectedRefs: 2,
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
			expectedRefs: 1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

			resolver, err := NewFromContainerImageDeepSquash(img)
			require.NoError(t, err)

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
			require.NoError(t, err)

			expectedRefs := c.expectedRefs
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

			if string(actual.Reference().RealPath) != c.resolvePath {
				t.Errorf("bad resolve path: '%s'!='%s'", string(actual.Reference().RealPath), c.resolvePath)
			}

			if c.resolvePath != "" && string(actual.Reference().RealPath) != actual.RealPath {
				t.Errorf("we should always prefer real paths over ones with links")
			}

			layer := img.FileCatalog.Layer(actual.Reference())

			if layer.Metadata.Index != c.resolveLayer {
				t.Errorf("bad resolve layer: '%d'!='%d'", layer.Metadata.Index, c.resolveLayer)
			}
		})
	}
}

func Test_ContainerImageDeepSquash_FilesByGlob(t *testing.T) {
	cases := []struct {
		name         string
		glob         string
		resolveLayer uint
		resolvePath  string
		expectedRefs int
	}{
		{
			name:         "link with previous data",
			glob:         "**/link-1",
			resolveLayer: 1,
			resolvePath:  "/file-1.txt",
			expectedRefs: 1,
		},
		{
			name:         "link with in layer data",
			glob:         "**/link-within",
			resolveLayer: 5,
			resolvePath:  "/file-3.txt",
			expectedRefs: 1,
		},
		{
			name:         "link with overridden data",
			glob:         "**/link-2",
			resolveLayer: 7,
			resolvePath:  "/file-2.txt",
			expectedRefs: 2,
		},
		{
			name:         "indirect link (with overridden data)",
			glob:         "**/link-indirect",
			resolveLayer: 7,
			resolvePath:  "/file-2.txt",
			expectedRefs: 2,
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
			expectedRefs: 2,
		},
		{
			name:         "parent is a link (override)",
			glob:         "**/parent-link/file-4.txt",
			resolveLayer: 11,
			resolvePath:  "/parent/file-4.txt",
			expectedRefs: 2,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

			resolver, err := NewFromContainerImageDeepSquash(img)
			require.NoError(t, err)

			refs, err := resolver.FilesByGlob(c.glob)
			require.NoError(t, err)

			expectedRefs := c.expectedRefs
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

			if string(actual.Reference().RealPath) != c.resolvePath {
				t.Errorf("bad resolve path: '%s'!='%s'", string(actual.Reference().RealPath), c.resolvePath)
			}

			if c.resolvePath != "" && string(actual.Reference().RealPath) != actual.RealPath {
				t.Errorf("we should always prefer real paths over ones with links")
			}

			layer := img.FileCatalog.Layer(actual.Reference())

			if layer.Metadata.Index != c.resolveLayer {
				t.Errorf("bad resolve layer: '%d'!='%d'", layer.Metadata.Index, c.resolveLayer)
			}
		})
	}
}

func Test_ContainerImageDeepSquash_FilesByMIMEType(t *testing.T) {

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

			resolver, err := NewFromContainerImageDeepSquash(img)
			assert.NoError(t, err)

			locations, err := resolver.FilesByMIMEType(test.mimeType)
			assert.NoError(t, err)

			assert.Len(t, locations, test.expectedPaths.Size())
			for _, l := range locations {
				assert.True(t, test.expectedPaths.Has(l.RealPath), "does not have path %q", l.RealPath)
			}
		})
	}
}

func Test_ContainerImageDeepSquash_hasFilesystemIDInLocation(t *testing.T) {
	img := imagetest.GetFixtureImage(t, "docker-archive", "image-duplicate-path")

	resolver, err := NewFromContainerImageDeepSquash(img)
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

func Test_ContainerImageDeepSquash_FilesContents(t *testing.T) {

	tests := []struct {
		name     string
		path     string
		contents []string
	}{
		{
			name: "one degree",
			path: "link-2",
			contents: []string{
				"NEW file override!",
				"file 2!",
			},
		},
		{
			name: "two degrees",
			path: "link-indirect",
			contents: []string{
				"NEW file override!",
				"file 2!",
			},
		},
		{
			name:     "dead link",
			path:     "link-dead",
			contents: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

			resolver, err := NewFromContainerImageDeepSquash(img)
			assert.NoError(t, err)

			refs, err := resolver.FilesByPath(test.path)
			require.NoError(t, err)
			assert.Len(t, refs, len(test.contents))

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

func Test_ContainerImageDeepSquash_FilesContents_errorOnDirRequest(t *testing.T) {
	img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

	resolver, err := NewFromContainerImageDeepSquash(img)
	assert.NoError(t, err)

	var dirLoc *file.Location
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for loc := range resolver.AllLocations(ctx) {
		// this is known to be a directory in the test fixture
		if dirLoc == nil && loc.RealPath == "/parent" {
			dirLoc = &loc
		}
	}

	require.NotNil(t, dirLoc)

	reader, err := resolver.FileContentsByLocation(*dirLoc)
	require.Error(t, err)
	require.Nil(t, reader)
}

func Test_ContainerImageDeepSquash_resolvesLinks(t *testing.T) {
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
				file.NewVirtualLocation("/file-3.txt", "/file-3.txt"),
				file.NewVirtualLocation("/file-2.txt", "/file-2.txt"),
				file.NewVirtualLocation("/file-2.txt", "/file-2.txt"),
				file.NewVirtualLocation("/parent/file-4.txt", "/parent/file-4.txt"),
				file.NewVirtualLocation("/parent/file-4.txt", "/parent/file-4.txt"),
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
				file.NewVirtualLocation("/file-2.txt", "/link-2"),
				file.NewVirtualLocation("/file-2.txt", "/link-2"),

				// though this is a link, and it matches to the file, the resolver de-duplicates files
				// by the real path, so it is not included in the results
				//file.NewVirtualLocation("/file-2.txt", "/link-indirect"),

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
				// this has two copies in the base image, which overwrites the same location
				file.NewVirtualLocation("/file-2.txt", "/file-2.txt"),
				file.NewVirtualLocation("/file-2.txt", "/file-2.txt"),
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
				file.NewVirtualLocation("/file-2.txt", "/file-2.txt"),
				file.NewVirtualLocation("/file-2.txt", "/file-2.txt"),
				file.NewVirtualLocation("/file-3.txt", "/file-3.txt"),
				file.NewVirtualLocation("/parent/file-4.txt", "/parent/file-4.txt"),
				file.NewVirtualLocation("/parent/file-4.txt", "/parent/file-4.txt"),
			},
		},
		{
			name: "by basename glob to links",
			runner: func(resolver file.Resolver) []file.Location {
				actualLocations, err := resolver.FilesByGlob("**/link-*")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []file.Location{
				file.NewVirtualLocation("/file-1.txt", "/link-1"),
				file.NewVirtualLocation("/file-2.txt", "/link-2"),
				file.NewVirtualLocation("/file-2.txt", "/link-2"),

				// we already have this real file path via another link, so only one is returned
				// file.NewVirtualLocation("/file-2.txt", "/link-indirect"),

				file.NewVirtualLocation("/file-3.txt", "/link-within"),
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
				file.NewVirtualLocation("/file-2.txt", "/file-2.txt"),
				file.NewVirtualLocation("/file-2.txt", "/file-2.txt"),
				file.NewVirtualLocation("/file-3.txt", "/file-3.txt"),
				file.NewVirtualLocation("/parent/file-4.txt", "/parent/file-4.txt"),
				file.NewVirtualLocation("/parent/file-4.txt", "/parent/file-4.txt"),
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

			resolver, err := NewFromContainerImageDeepSquash(img)
			assert.NoError(t, err)

			actual := test.runner(resolver)

			compareLocations(t, test.expected, actual)
		})
	}

}

func Test_ContainerImageDeepSquash_AllLocations(t *testing.T) {
	img := imagetest.GetFixtureImage(t, "docker-archive", "image-files-deleted")

	resolver, err := NewFromContainerImageDeepSquash(img)
	assert.NoError(t, err)

	paths := strset.New()
	for loc := range resolver.AllLocations(context.Background()) {
		paths.Add(loc.RealPath)
	}
	expected := []string{
		"/Dockerfile",
		"/file-3.txt",
		"/target",
		"/target/file-2.txt",
	}

	// depending on how the image is built (either from linux or mac), sys and proc might accidentally be added to the image.
	// this isn't important for the test, so we remove them.
	paths.Remove("/proc", "/sys", "/dev", "/etc")

	// remove cache created by Mac Rosetta when emulating different arches
	paths.Remove("/.cache/rosetta", "/.cache")

	pathsList := paths.List()
	sort.Strings(pathsList)

	assert.ElementsMatchf(t, expected, pathsList, "expected all paths to be indexed, but found different paths: \n%s", cmp.Diff(expected, paths.List()))
}

func TestContainerImageDeepSquash_MergeLocations(t *testing.T) {
	tests := []struct {
		name                string
		squashedLocations   file.LocationSet
		allLayersLocations  file.LocationSet
		expectedLocations   int
		expectedVisibleOnly bool
	}{
		{
			name:                "empty squashed locations returns empty",
			squashedLocations:   file.NewLocationSet(),
			allLayersLocations:  file.NewLocationSet(makeLocation("/some/path", 1)),
			expectedLocations:   0,
			expectedVisibleOnly: false,
		},
		{
			name: "only squashed locations returns all as visible",
			squashedLocations: file.NewLocationSet(
				makeLocation("/path/one", 1),
				makeLocation("/path/two", 1),
			),
			allLayersLocations:  file.NewLocationSet(),
			expectedLocations:   2,
			expectedVisibleOnly: true,
		},
		{
			name:                "deduplicates matching locations between squashed and all layers + additional hidden locations",
			squashedLocations:   file.NewLocationSet(makeLocation("/path/one", 2)),
			allLayersLocations:  file.NewLocationSet(makeLocation("/path/one", 2), makeLocation("/path/one", 1)),
			expectedLocations:   2,
			expectedVisibleOnly: false,
		},
		{
			name:                "deduplicates matching locations between squashed and all layers",
			squashedLocations:   file.NewLocationSet(makeLocation("/path/one", 1)),
			allLayersLocations:  file.NewLocationSet(makeLocation("/path/one", 1)),
			expectedLocations:   1,
			expectedVisibleOnly: true,
		},
		{
			name:              "all layers locations with paths not in squashed tree are excluded",
			squashedLocations: file.NewLocationSet(makeLocation("/path/one", 1)),
			allLayersLocations: file.NewLocationSet(
				makeLocation("/path/one", 1),             // layer 2 version will be skipped (deduped)
				makeLocation("/path/not/in/squashed", 2), // will be excluded due to path not in squashed
			),
			expectedLocations:   1,
			expectedVisibleOnly: true,
		},
		{
			name:              "includes hidden locations from all layers when path in squashed tree",
			squashedLocations: file.NewLocationSet(makeLocation("/path/one", 1), makeLocation("/path/two", 2)),
			allLayersLocations: file.NewLocationSet(
				makeLocation("/path/one", 1), // will be deduped
				makeLocation("/path/one", 2), // will be included as hidden
				makeLocation("/path/two", 2), // will be deduped
				makeLocation("/path/two", 3), // will be included as hidden
				makeLocation("/path/two", 4), // will be included as hidden
			),
			expectedLocations:   5, // 2 from squashed + 3 from layers for path/two
			expectedVisibleOnly: false,
		},
		{
			name: "complex scenario with multiple paths and layers",
			squashedLocations: file.NewLocationSet(
				makeLocation("/bin/bash", 1),
				makeLocation("/etc/passwd", 2),
				makeLocation("/var/log/syslog", 3),
			),
			allLayersLocations: file.NewLocationSet(
				makeLocation("/bin/bash", 1),          // will be deduped
				makeLocation("/bin/bash", 0),          // will be included as hidden
				makeLocation("/etc/passwd", 2),        // will be deduped
				makeLocation("/etc/passwd", 0),        // will be included as hidden
				makeLocation("/var/log/syslog", 3),    // will be deduped
				makeLocation("/var/log/syslog", 0),    // will be included as hidden
				makeLocation("/tmp/not-in-squash", 4), // will be excluded - not in squashed
			),
			expectedLocations:   6, // 3 from squashed + 3 hidden from all layers
			expectedVisibleOnly: false,
		},
		{
			name: "include virtual locations",
			squashedLocations: file.NewLocationSet(
				makeLocation("/path/one", 1),
				makeLocation("/path/two", 2),
				makeLocation("/path/to-one", 2), // a symlink
			),
			allLayersLocations: file.NewLocationSet(
				makeLocation("/path/one", 1), // will be deduped
				makeVirtualLocation("/path/one", "/path/to-one", 2),
			),
			expectedLocations:   4,
			expectedVisibleOnly: false,
		},
		{
			name: "don't include hidden virtual locations",
			squashedLocations: file.NewLocationSet(
				makeLocation("/path/one", 1),
			),
			allLayersLocations: file.NewLocationSet(
				makeLocation("/path/one", 1),                        // will be deduped
				makeVirtualLocation("/path/one", "/path/to-one", 2), // would have been included if /path/to-one was in the squash tree
			),
			expectedLocations:   1,
			expectedVisibleOnly: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			resolver := &ContainerImageDeepSquash{
				squashed:  newMockSimpleResolver(tt.squashedLocations.ToSlice()),
				allLayers: newMockSimpleResolver(tt.allLayersLocations.ToSlice()),
			}

			squashedLocations := tt.squashedLocations.ToSlice()
			allLayersLocations := tt.allLayersLocations.ToSlice()

			mergedLocations := resolver.mergeLocations(squashedLocations, allLayersLocations)

			require.Len(t, mergedLocations, tt.expectedLocations, "incorrect number of merged locations (expected %d, found %d)", tt.expectedLocations, len(mergedLocations))

			if tt.expectedLocations > 0 {
				onlyVisible := true
				for _, loc := range mergedLocations {
					if annotation, ok := loc.Annotations[file.VisibleAnnotationKey]; ok {
						if annotation != file.VisibleAnnotation {
							onlyVisible = false
							break
						}
					}
				}
				assert.Equal(t, tt.expectedVisibleOnly, onlyVisible, "visibility annotation check failed")

			}

			visibleCount := 0
			hiddenCount := 0
			for _, loc := range mergedLocations {
				if annotation, ok := loc.Annotations[file.VisibleAnnotationKey]; ok {
					if annotation == file.VisibleAnnotation {
						visibleCount++
					} else if annotation == file.HiddenAnnotation {
						hiddenCount++
					}
				}
			}

			// for test cases where we expect some hidden annotations...
			if !tt.expectedVisibleOnly && tt.expectedLocations > 0 {
				assert.Greater(t, hiddenCount, 0, "expected some hidden locations but found none")
				assert.Greater(t, visibleCount, 0, "expected some visible locations but found none")
			}

			// for test cases where we expect only visible annotations...
			if tt.expectedVisibleOnly && tt.expectedLocations > 0 {
				assert.Equal(t, tt.expectedLocations, visibleCount, "incorrect number of visible locations")
				assert.Equal(t, 0, hiddenCount, "found hidden locations when expecting only visible")
			}
		})
	}
}

func TestContainerImageDeepSquash_MergeLocationStreams(t *testing.T) {
	tests := []struct {
		name                string
		squashedLocations   []file.Location
		allLayersLocations  []file.Location
		expectedLocations   int
		expectedVisibleOnly bool
	}{
		{
			name:                "empty squashed locations returns empty",
			squashedLocations:   []file.Location{},
			allLayersLocations:  []file.Location{makeLocation("/some/path", 1)},
			expectedLocations:   0,
			expectedVisibleOnly: false,
		},
		{
			name: "only squashed locations returns all as visible",
			squashedLocations: []file.Location{
				makeLocation("/path/one", 1),
				makeLocation("/path/two", 1),
			},
			allLayersLocations:  []file.Location{},
			expectedLocations:   2,
			expectedVisibleOnly: true,
		},
		{
			name:                "exact match locations are deduped",
			squashedLocations:   []file.Location{makeLocation("/path/one", 1)},
			allLayersLocations:  []file.Location{makeLocation("/path/one", 1)},
			expectedLocations:   1,
			expectedVisibleOnly: true,
		},
		{
			name:                "different layers same path not deduped",
			squashedLocations:   []file.Location{makeLocation("/path/one", 2)},
			allLayersLocations:  []file.Location{makeLocation("/path/one", 1)},
			expectedLocations:   2, // 1 visible from squashed + 1 hidden from all layers
			expectedVisibleOnly: false,
		},
		{
			name:              "all layers with path not in squashed are excluded",
			squashedLocations: []file.Location{makeLocation("/path/one", 1)},
			allLayersLocations: []file.Location{
				makeLocation("/path/one", 2),
				makeLocation("/not/in/squashed", 3),
			},
			expectedLocations:   2, // 1 from squashed + 1 from all layers (path/one)
			expectedVisibleOnly: false,
		},
		{
			name: "includes all layer versions for paths in squashed",
			squashedLocations: []file.Location{
				makeLocation("/path/one", 3),
				makeLocation("/path/two", 2),
			},
			allLayersLocations: []file.Location{
				makeLocation("/path/one", 1),
				makeLocation("/path/one", 2),
				makeLocation("/path/two", 2), // will be deduped
				makeLocation("/path/two", 3),
				makeLocation("/path/two", 4),
			},
			expectedLocations:   6, // 2 from squashed + 4 from all layers
			expectedVisibleOnly: false,
		},
		{
			name: "complex scenario with multiple paths and layers",
			squashedLocations: []file.Location{
				makeLocation("/bin/bash", 5),
				makeLocation("/etc/passwd", 3),
				makeLocation("/var/log/syslog", 2),
			},
			allLayersLocations: []file.Location{
				makeLocation("/bin/bash", 1),
				makeLocation("/bin/bash", 2),
				makeLocation("/bin/bash", 3),
				makeLocation("/bin/bash", 4),
				makeLocation("/bin/bash", 5), // will be deduped
				makeLocation("/etc/passwd", 1),
				makeLocation("/etc/passwd", 2),
				makeLocation("/etc/passwd", 3), // will be deduped
				makeLocation("/var/log/syslog", 1),
				makeLocation("/var/log/syslog", 2),    // will be deduped
				makeLocation("/tmp/not-in-squash", 1), // not included
			},
			expectedLocations:   10, // 3 from squashed + 7 from all layers (3 excluded due to dedup/path)
			expectedVisibleOnly: false,
		},
		{
			name: "include virtual locations",
			squashedLocations: []file.Location{
				makeLocation("/path/one", 1),
				makeLocation("/path/two", 2),
				makeLocation("/path/to-one", 2), // a symlink
			},
			allLayersLocations: []file.Location{
				makeLocation("/path/one", 1), // will be deduped
				makeVirtualLocation("/path/one", "/path/to-one", 2),
			},
			expectedLocations:   4,
			expectedVisibleOnly: false,
		},
		{
			name: "don't include hidden virtual locations",
			squashedLocations: []file.Location{
				makeLocation("/path/one", 1),
			},
			allLayersLocations: []file.Location{
				makeLocation("/path/one", 1),                        // will be deduped
				makeVirtualLocation("/path/one", "/path/to-one", 2), // would have been included if /path/to-one was in the squash tree
			},
			expectedLocations:   1,
			expectedVisibleOnly: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			resolver := &ContainerImageDeepSquash{
				squashed: newMockSimpleResolver(tt.squashedLocations),
			}

			squashedChan := make(chan file.Location)
			allLayersChan := make(chan file.Location)

			wg := &sync.WaitGroup{}
			wg.Add(2)

			go func() {
				defer wg.Done()
				defer close(squashedChan)
				for _, loc := range tt.squashedLocations {
					squashedChan <- loc
				}
			}()

			go func() {
				defer wg.Done()
				defer close(allLayersChan)
				for _, loc := range tt.allLayersLocations {
					allLayersChan <- loc
				}
			}()

			mergedChan := resolver.mergeLocationStreams(ctx, squashedChan, allLayersChan)

			var mergedLocations []file.Location
			for loc := range mergedChan {
				mergedLocations = append(mergedLocations, loc)
			}

			assert.Equal(t, tt.expectedLocations, len(mergedLocations), "incorrect number of merged locations")

			visibleCount := 0
			hiddenCount := 0
			duplicateFound := false

			// track seen locations to verify deduplication
			seenLocations := make(map[file.LocationData]int)

			for _, loc := range mergedLocations {
				// check for duplicates
				seenLocations[loc.LocationData]++
				if seenLocations[loc.LocationData] > 1 {
					duplicateFound = true
				}

				// count annotations
				if annotation, ok := loc.Annotations[file.VisibleAnnotationKey]; ok {
					if annotation == file.VisibleAnnotation {
						visibleCount++
					} else if annotation == file.HiddenAnnotation {
						hiddenCount++
					}
				}
			}

			assert.False(t, duplicateFound, "found duplicate locations when none expected")

			// check visibility annotations
			if tt.expectedVisibleOnly && len(mergedLocations) > 0 {
				assert.Equal(t, len(mergedLocations), visibleCount,
					"incorrect number of visible locations")
				assert.Equal(t, 0, hiddenCount,
					"found hidden locations when expecting only visible")
			}

			if !tt.expectedVisibleOnly && len(mergedLocations) > 0 {
				assert.Greater(t, hiddenCount, 0,
					"expected some hidden locations but found none")
				assert.Greater(t, visibleCount, 0,
					"expected some visible locations but found none")
			}

			wg.Wait()

			goleak.VerifyNone(t)
		})
	}
}

func TestContainerImageDeepSquash_MergeLocationStreams_FunCases(t *testing.T) {

	t.Run("concurrent context cancellation", func(t *testing.T) {
		upstreamCtx, upstreamCancel := context.WithCancel(context.Background())

		ctx, cancel := context.WithCancel(context.Background())

		resolver := &ContainerImageDeepSquash{
			squashed: newMockSimpleResolver(nil),
		}

		squashedChan := make(chan file.Location)
		allLayersChan := make(chan file.Location)

		wg := &sync.WaitGroup{}
		wg.Add(2)

		go func() {
			defer wg.Done()
			defer close(squashedChan)

			count := 0
			for {
				count++
				loc := makeLocation(fmt.Sprintf("/path/%d", count), 2)
				select {
				case <-upstreamCtx.Done():
					return
				case squashedChan <- loc:
				}
			}
		}()

		go func() {
			defer wg.Done()
			defer close(allLayersChan)

			count := 0
			for {
				count++
				loc := makeLocation(fmt.Sprintf("/path/%d", count), 2)
				select {
				case <-upstreamCtx.Done():
					return
				case allLayersChan <- loc:
				}
			}
		}()

		mergedChan := resolver.mergeLocationStreams(ctx, squashedChan, allLayersChan)

		go func() {
			<-time.After(5 * time.Millisecond)
			cancel()
			time.Sleep(10 * time.Millisecond)
			upstreamCancel()
		}()

		for range mergedChan {
			// drain
		}
		wg.Wait()

		goleak.VerifyNone(t)
	})

	t.Run("empty streams", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		resolver := &ContainerImageDeepSquash{
			squashed: newMockSimpleResolver([]file.Location{}),
		}

		squashedChan := make(chan file.Location)
		allLayersChan := make(chan file.Location)
		close(squashedChan)
		close(allLayersChan)

		mergedChan := resolver.mergeLocationStreams(ctx, squashedChan, allLayersChan)

		var count int
		// should return immediately with no results (not block)
		for range mergedChan {
			count++
		}
		assert.Equal(t, 0, count, "expected no results from empty streams")
	})

	t.Run("squashed empty but all layers has data", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		resolver := &ContainerImageDeepSquash{
			squashed: newMockSimpleResolver([]file.Location{}),
		}

		squashedChan := make(chan file.Location)
		allLayersChan := make(chan file.Location)
		close(squashedChan)

		wg := &sync.WaitGroup{}
		wg.Add(1)

		go func() {
			defer close(allLayersChan)
			defer wg.Done()

			allLayersChan <- makeLocation("/path/one", 1)
		}()

		mergedChan := resolver.mergeLocationStreams(ctx, squashedChan, allLayersChan)

		// should return no results since squashed is empty
		var count int
		for range mergedChan {
			count++
		}

		wg.Wait()

		assert.Equal(t, 0, count, "expected no results when squashed is empty")
	})
}

func makeLocation(path string, layer int) file.Location {
	return file.NewLocationFromCoordinates(file.Coordinates{
		RealPath:     path,
		FileSystemID: fmt.Sprintf("layer-%d", layer),
	})
}

func makeVirtualLocation(path, access string, layer int) file.Location {
	return file.NewVirtualLocationFromCoordinates(file.Coordinates{
		RealPath:     path,
		FileSystemID: fmt.Sprintf("layer-%d", layer),
	}, access)
}
