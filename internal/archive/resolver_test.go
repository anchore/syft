package archive

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

// mockResolver implements file.Resolver for testing.
type mockResolver struct {
	locations map[string]file.Location // path -> location
	contents  map[string]string        // realPath -> content
}

func newMockResolver(files map[string]string) *mockResolver {
	r := &mockResolver{
		locations: make(map[string]file.Location),
		contents:  files,
	}
	for path := range files {
		r.locations[path] = file.NewLocation(path)
	}
	return r
}

func (m *mockResolver) HasPath(path string) bool {
	_, ok := m.locations[path]
	return ok
}

func (m *mockResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	var results []file.Location
	for _, p := range paths {
		if loc, ok := m.locations[p]; ok {
			results = append(results, loc)
		}
	}
	return results, nil
}

func (m *mockResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	var results []file.Location
	for _, pattern := range patterns {
		for path, loc := range m.locations {
			matched, _ := filepath.Match(pattern, path)
			if matched {
				results = append(results, loc)
			}
			// also try with the basename for simple glob patterns
			if !matched {
				matched, _ = filepath.Match(pattern, filepath.Base(path))
				if matched {
					results = append(results, loc)
				}
			}
		}
	}
	return results, nil
}

func (m *mockResolver) FilesByMIMEType(_ ...string) ([]file.Location, error) {
	return nil, nil
}

func (m *mockResolver) RelativeFileByPath(_ file.Location, path string) *file.Location {
	if loc, ok := m.locations[path]; ok {
		return &loc
	}
	return nil
}

func (m *mockResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	if content, ok := m.contents[location.RealPath]; ok {
		return io.NopCloser(strings.NewReader(content)), nil
	}
	return nil, os.ErrNotExist
}

func (m *mockResolver) AllLocations(ctx context.Context) <-chan file.Location {
	ch := make(chan file.Location)
	go func() {
		defer close(ch)
		for _, loc := range m.locations {
			select {
			case <-ctx.Done():
				return
			case ch <- loc:
			}
		}
	}()
	return ch
}

func (m *mockResolver) FileMetadataByLocation(_ file.Location) (file.Metadata, error) {
	return file.Metadata{}, nil
}

// strictMockResolver mimics real directory resolvers (fileresolver.Directory) which
// require that FileContentsByLocation receives a location object that was originally
// returned by FilesByPath/FilesByGlob — not a freshly constructed file.NewLocation().
// Real directory resolvers need the internal stereoscope file.Reference for index lookup.
// We simulate this by annotating returned locations and only accepting those back.
type strictMockResolver struct {
	mockResolver
	resolvedAnnotation string // annotation key that marks locations as "resolved"
}

func newStrictMockResolver(files map[string]string) *strictMockResolver {
	return &strictMockResolver{
		mockResolver:       *newMockResolver(files),
		resolvedAnnotation: "strict-resolved",
	}
}

func (s *strictMockResolver) annotate(loc file.Location) file.Location {
	return loc.WithAnnotation(s.resolvedAnnotation, "true")
}

func (s *strictMockResolver) isResolved(loc file.Location) bool {
	return loc.Annotations[s.resolvedAnnotation] == "true"
}

func (s *strictMockResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	locs, err := s.mockResolver.FilesByPath(paths...)
	for i := range locs {
		locs[i] = s.annotate(locs[i])
	}
	return locs, err
}

func (s *strictMockResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	locs, err := s.mockResolver.FilesByGlob(patterns...)
	for i := range locs {
		locs[i] = s.annotate(locs[i])
	}
	return locs, err
}

func (s *strictMockResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	if !s.isResolved(location) {
		return nil, fmt.Errorf("location %q was not resolved via FilesByPath/FilesByGlob first (simulating real directory resolver behavior)", location.RealPath)
	}
	return s.mockResolver.FileContentsByLocation(location)
}

func (s *strictMockResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	if !s.isResolved(location) {
		return file.Metadata{}, fmt.Errorf("location %q was not resolved via FilesByPath/FilesByGlob first", location.RealPath)
	}
	return s.mockResolver.FileMetadataByLocation(location)
}

// TestCompositeResolver_FileContentsByLocation_ChildRequiresLookup tests that
// FileContentsByLocation works when the child resolver requires locations to be
// resolved via FilesByPath first (as real directory resolvers do). This catches
// the bug where we constructed a bare file.NewLocation() without a valid internal
// reference, which fails on real fileresolver.Directory implementations.
func TestCompositeResolver_FileContentsByLocation_ChildRequiresLookup(t *testing.T) {
	parent := newMockResolver(map[string]string{})
	child := newStrictMockResolver(map[string]string{
		"/lib/data.txt": "important data",
	})

	composite := NewCompositeResolver(parent)
	archiveLoc := file.NewLocation("/archive.zip")
	fsID := composite.AddChild(child, archiveLoc, 1)

	// Simulate what a cataloger does: find the file, then read its content.
	// The location returned has the archive's fsID, not the child's internal ref.
	locs, err := composite.FilesByPath("/lib/data.txt")
	require.NoError(t, err)
	require.Len(t, locs, 1)
	assert.Equal(t, fsID, locs[0].FileSystemID)

	// Now read content - this must work even though the location was transformed
	reader, err := composite.FileContentsByLocation(locs[0])
	require.NoError(t, err, "FileContentsByLocation should resolve the file in the child resolver via FilesByPath before reading")
	defer reader.Close()

	content, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, "important data", string(content))
}

// TestCompositeResolver_FileMetadataByLocation_ChildRequiresLookup is the same
// test as above but for FileMetadataByLocation.
func TestCompositeResolver_FileMetadataByLocation_ChildRequiresLookup(t *testing.T) {
	parent := newMockResolver(map[string]string{})
	child := newStrictMockResolver(map[string]string{
		"/lib/data.txt": "important data",
	})

	composite := NewCompositeResolver(parent)
	archiveLoc := file.NewLocation("/archive.zip")
	fsID := composite.AddChild(child, archiveLoc, 1)

	locs, err := composite.FilesByPath("/lib/data.txt")
	require.NoError(t, err)
	require.Len(t, locs, 1)
	assert.Equal(t, fsID, locs[0].FileSystemID)

	// FileMetadataByLocation must also resolve via FilesByPath first
	_, err = composite.FileMetadataByLocation(locs[0])
	require.NoError(t, err, "FileMetadataByLocation should resolve the file in the child resolver via FilesByPath before reading metadata")
}

func TestCompositeResolver_FilesByPath_ParentOnly(t *testing.T) {
	parent := newMockResolver(map[string]string{
		"/parent.txt": "parent content",
	})
	composite := NewCompositeResolver(parent)

	locs, err := composite.FilesByPath("/parent.txt")
	require.NoError(t, err)
	require.Len(t, locs, 1)
	assert.Equal(t, "/parent.txt", locs[0].RealPath)
}

func TestCompositeResolver_FilesByPath_WithChild(t *testing.T) {
	parent := newMockResolver(map[string]string{
		"/parent.txt": "parent content",
	})
	child := newMockResolver(map[string]string{
		"/child.txt": "child content",
	})

	composite := NewCompositeResolver(parent)
	archiveLoc := file.NewLocation("/archive.tar.gz")
	composite.AddChild(child, archiveLoc, 1)

	locs, err := composite.FilesByPath("/child.txt")
	require.NoError(t, err)
	require.Len(t, locs, 1)
	assert.Contains(t, locs[0].AccessPath, "archive.tar.gz:")
	assert.Contains(t, locs[0].AccessPath, "child.txt")
}

func TestCompositeResolver_FileContentsByLocation_Parent(t *testing.T) {
	parent := newMockResolver(map[string]string{
		"/parent.txt": "parent content",
	})
	composite := NewCompositeResolver(parent)

	locs, err := composite.FilesByPath("/parent.txt")
	require.NoError(t, err)
	require.Len(t, locs, 1)

	reader, err := composite.FileContentsByLocation(locs[0])
	require.NoError(t, err)
	defer reader.Close()

	content, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, "parent content", string(content))
}

func TestCompositeResolver_FileContentsByLocation_Child(t *testing.T) {
	parent := newMockResolver(map[string]string{})
	child := newMockResolver(map[string]string{
		"/child.txt": "child content",
	})

	composite := NewCompositeResolver(parent)
	archiveLoc := file.NewLocation("/archive.zip")
	fsID := composite.AddChild(child, archiveLoc, 1)

	// construct a location as returned by FilesByPath
	loc := file.Location{
		LocationData: file.LocationData{
			Coordinates: file.Coordinates{
				RealPath:     "/child.txt",
				FileSystemID: fsID,
			},
			AccessPath: "/archive.zip:/child.txt",
		},
	}

	reader, err := composite.FileContentsByLocation(loc)
	require.NoError(t, err)
	defer reader.Close()

	content, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, "child content", string(content))
}

func TestCompositeResolver_HasPath(t *testing.T) {
	parent := newMockResolver(map[string]string{
		"/parent.txt": "p",
	})
	child := newMockResolver(map[string]string{
		"/child.txt": "c",
	})

	composite := NewCompositeResolver(parent)
	archiveLoc := file.NewLocation("/archive.zip")
	composite.AddChild(child, archiveLoc, 1)

	assert.True(t, composite.HasPath("/parent.txt"))
	assert.True(t, composite.HasPath("/child.txt"))
	assert.False(t, composite.HasPath("/nonexistent.txt"))
}

func TestCompositeResolver_AllLocations(t *testing.T) {
	parent := newMockResolver(map[string]string{
		"/parent.txt": "p",
	})
	child := newMockResolver(map[string]string{
		"/child.txt": "c",
	})

	composite := NewCompositeResolver(parent)
	archiveLoc := file.NewLocation("/archive.zip")
	composite.AddChild(child, archiveLoc, 1)

	ctx := context.Background()
	var allLocs []file.Location
	for loc := range composite.AllLocations(ctx) {
		allLocs = append(allLocs, loc)
	}

	assert.Len(t, allLocs, 2)

	hasArchivePrefix := false
	for _, loc := range allLocs {
		if strings.Contains(loc.AccessPath, "archive.zip:") {
			hasArchivePrefix = true
			break
		}
	}
	assert.True(t, hasArchivePrefix)
}

func TestCompositeResolver_ChildCount(t *testing.T) {
	parent := newMockResolver(map[string]string{})
	composite := NewCompositeResolver(parent)
	assert.Equal(t, 0, composite.ChildCount())

	child := newMockResolver(map[string]string{"/a.txt": "a"})
	archiveLoc := file.NewLocation("/archive.zip")
	composite.AddChild(child, archiveLoc, 1)
	assert.Equal(t, 1, composite.ChildCount())
}

func TestCompositeResolver_TransformLocation(t *testing.T) {
	composite := NewCompositeResolver(nil)

	archiveLoc := file.NewLocation("/path/to/archive.tar.gz")
	child := &childResolver{
		archiveLocation: archiveLoc,
		fsID:            "archive:abc123",
		depth:           1,
	}

	loc := file.NewLocation("/inner/file.txt")
	transformed := composite.transformLocation(loc, child)

	assert.Equal(t, "/inner/file.txt", transformed.RealPath)
	assert.Equal(t, "archive:abc123", transformed.FileSystemID)
	assert.Equal(t, "/path/to/archive.tar.gz:/inner/file.txt", transformed.AccessPath)
}

func TestGenerateArchiveFSID(t *testing.T) {
	loc1 := file.NewLocation("/archive1.zip")
	loc2 := file.NewLocation("/archive2.zip")

	fsID1 := generateArchiveFSID(loc1)
	fsID2 := generateArchiveFSID(loc2)

	assert.NotEqual(t, fsID1, fsID2)
	assert.Equal(t, fsID1, generateArchiveFSID(loc1))
	assert.True(t, strings.HasPrefix(fsID1, "archive:"))
}

func TestCompositeResolver_MultipleChildren(t *testing.T) {
	parent := newMockResolver(map[string]string{
		"/base.txt": "base",
	})
	child1 := newMockResolver(map[string]string{
		"/lib.so": "library1",
	})
	child2 := newMockResolver(map[string]string{
		"/lib.so": "library2",
	})

	composite := NewCompositeResolver(parent)
	composite.AddChild(child1, file.NewLocation("/archive1.zip"), 1)
	composite.AddChild(child2, file.NewLocation("/archive2.zip"), 1)

	assert.Equal(t, 2, composite.ChildCount())

	// searching for /lib.so should find it in both children
	locs, err := composite.FilesByPath("/lib.so")
	require.NoError(t, err)
	assert.Len(t, locs, 2)

	// each should have different archive prefixes
	var accessPaths []string
	for _, loc := range locs {
		accessPaths = append(accessPaths, loc.AccessPath)
	}
	assert.Contains(t, accessPaths[0], "archive1.zip:")
	assert.Contains(t, accessPaths[1], "archive2.zip:")
}

func TestCompositeResolver_NoChildren_BehavesLikeParent(t *testing.T) {
	parent := newMockResolver(map[string]string{
		"/file.txt": "content",
	})
	composite := NewCompositeResolver(parent)

	// FilesByPath
	parentLocs, _ := parent.FilesByPath("/file.txt")
	compositeLocs, _ := composite.FilesByPath("/file.txt")
	assert.Equal(t, len(parentLocs), len(compositeLocs))

	// HasPath
	assert.Equal(t, parent.HasPath("/file.txt"), composite.HasPath("/file.txt"))
	assert.Equal(t, parent.HasPath("/nope"), composite.HasPath("/nope"))
}
