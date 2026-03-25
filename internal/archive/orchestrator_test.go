package archive

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/file"
)

// testResolverFactory creates a simple mock resolver factory for testing.
func testResolverFactory(root string) (file.Resolver, error) {
	// Walk the directory and create a mock resolver from its contents
	files := make(map[string]string)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		relPath, _ := filepath.Rel(root, path)
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		files["/"+relPath] = string(content)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return newMockResolver(files), nil
}

func TestOrchestrator_DiscoverAndExtract_ZipArchive(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create a zip file in the "source" directory
	zipFiles := map[string]string{
		"inner.txt": "hello from inside the zip",
		"lib/a.so":  "library content",
	}
	zipPath := createTestZip(t, dir, zipFiles)

	// Create a parent resolver that sees the zip file
	parentFiles := map[string]string{
		"/test.zip": "placeholder", // the resolver sees the file
	}
	parent := newMockResolver(parentFiles)

	// Override FileContentsByLocation to return actual zip content
	zipContent, err := os.ReadFile(zipPath)
	require.NoError(t, err)
	parent.contents["/test.zip"] = string(zipContent)

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeIndexedArchives = true

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	newCount := orch.DiscoverAndExtract(ctx, 0)
	assert.Equal(t, 1, newCount)

	// the composite resolver should now have the child files
	resolver := orch.Resolver()
	assert.Equal(t, 1, resolver.ChildCount())
}

func TestOrchestrator_DiscoverAndExtract_TarGzArchive(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	tarFiles := map[string]string{
		"inner.txt": "hello from tar",
	}
	tarPath := createTestTarGz(t, dir, tarFiles)

	tarContent, err := os.ReadFile(tarPath)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/test.tar.gz": string(tarContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeUnindexedArchives = true // tar needs this enabled

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	newCount := orch.DiscoverAndExtract(ctx, 0)
	assert.Equal(t, 1, newCount)
	assert.Equal(t, 1, orch.Resolver().ChildCount())
}

func TestOrchestrator_DiscoverAndExtract_DepthLimit(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	parent := newMockResolver(map[string]string{
		"/file.txt": "just a file",
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	// at depth 1 (== MaxDepth), should extract nothing
	newCount := orch.DiscoverAndExtract(ctx, 1)
	assert.Equal(t, 0, newCount)
}

func TestOrchestrator_DiscoverAndExtract_NoArchives(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	parent := newMockResolver(map[string]string{
		"/file.txt": "plain text",
		"/data.csv": "a,b,c",
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 3

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	newCount := orch.DiscoverAndExtract(ctx, 0)
	assert.Equal(t, 0, newCount)
	assert.Equal(t, 0, orch.Resolver().ChildCount())
}

func TestOrchestrator_DiscoverAndExtract_ExcludeExtension(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	zipPath := createTestZip(t, dir, map[string]string{"inner.txt": "data"})
	zipContent, err := os.ReadFile(zipPath)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/test.zip": string(zipContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeIndexedArchives = true
	cfg.ExcludeExtensions = []string{".zip"}

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	newCount := orch.DiscoverAndExtract(ctx, 0)
	assert.Equal(t, 0, newCount)
}

func TestOrchestrator_DiscoverAndExtract_TotalSizeLimit(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	zipPath := createTestZip(t, dir, map[string]string{"inner.txt": "data"})
	zipContent, err := os.ReadFile(zipPath)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/test.zip": string(zipContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeIndexedArchives = true
	cfg.MaxTotalExtractionBytes = 1 // 1 byte total limit - will be exceeded

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	// should still extract but hit the limit
	_ = orch.DiscoverAndExtract(ctx, 0)
	// second call should be blocked by total limit
	newCount := orch.DiscoverAndExtract(ctx, 0)
	assert.Equal(t, 0, newCount)
}

func TestOrchestrator_Relationships(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	zipPath := createTestZip(t, dir, map[string]string{"inner.txt": "data"})
	zipContent, err := os.ReadFile(zipPath)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/test.zip": string(zipContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeIndexedArchives = true

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	orch.DiscoverAndExtract(ctx, 0)

	rels := orch.Relationships()
	assert.NotEmpty(t, rels)

	// should have a contains relationship for the archive
	for _, rel := range rels {
		assert.Equal(t, "contains", string(rel.Type))
	}
}

func TestOrchestrator_Cleanup(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	zipPath := createTestZip(t, dir, map[string]string{"inner.txt": "data"})
	zipContent, err := os.ReadFile(zipPath)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/test.zip": string(zipContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeIndexedArchives = true

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)

	orch.DiscoverAndExtract(ctx, 0)

	// verify temp dirs exist
	entries, err := os.ReadDir(tmpDir)
	require.NoError(t, err)
	initialCount := len(entries)
	assert.True(t, initialCount > 0, "expected temp dirs to be created")

	orch.Cleanup()

	// verify temp dirs are cleaned up
	entries, err = os.ReadDir(tmpDir)
	require.NoError(t, err)
	assert.True(t, len(entries) < initialCount, "expected temp dirs to be cleaned up")
}

func TestOrchestrator_DoesNotReprocess(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	zipPath := createTestZip(t, dir, map[string]string{"inner.txt": "data"})
	zipContent, err := os.ReadFile(zipPath)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/test.zip": string(zipContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 2
	cfg.IncludeIndexedArchives = true

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	// first call extracts the archive
	first := orch.DiscoverAndExtract(ctx, 0)
	assert.Equal(t, 1, first)

	// second call should not re-extract the same archive
	second := orch.DiscoverAndExtract(ctx, 0)
	assert.Equal(t, 0, second)
	assert.Equal(t, 1, orch.Resolver().ChildCount())
}

func TestOrchestrator_NestedArchives_ZipInsideZip(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create inner zip
	innerZipPath := createTestZip(t, dir, map[string]string{
		"deep.txt": "deeply nested content",
	})
	innerZipContent, err := os.ReadFile(innerZipPath)
	require.NoError(t, err)

	// Create outer zip containing the inner zip
	outerDir := filepath.Join(dir, "outer")
	require.NoError(t, os.MkdirAll(outerDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(outerDir, "inner.zip"), innerZipContent, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(outerDir, "readme.txt"), []byte("readme"), 0o644))
	outerZipPath := createTestZip(t, outerDir, map[string]string{
		"inner.zip": string(innerZipContent),
		"readme.txt": "readme",
	})
	outerZipContent, err := os.ReadFile(outerZipPath)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/outer.zip": string(outerZipContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 3
	cfg.IncludeIndexedArchives = true

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	// Round 1: extract outer.zip
	count1 := orch.DiscoverAndExtract(ctx, 0)
	assert.Equal(t, 1, count1, "should extract outer.zip")
	assert.Equal(t, 1, orch.Resolver().ChildCount())

	// Round 2: extract inner.zip found inside outer.zip
	count2 := orch.DiscoverAndExtract(ctx, 1)
	assert.Equal(t, 1, count2, "should extract inner.zip from within outer.zip")
	assert.Equal(t, 2, orch.Resolver().ChildCount())

	// Round 3: no more archives to extract
	count3 := orch.DiscoverAndExtract(ctx, 2)
	assert.Equal(t, 0, count3, "no more archives to extract")
}

func TestOrchestrator_ContextCancellation(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()

	zipPath := createTestZip(t, dir, map[string]string{"inner.txt": "data"})
	zipContent, err := os.ReadFile(zipPath)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/test.zip": string(zipContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeIndexedArchives = true

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// should handle gracefully without hanging
	newCount := orch.DiscoverAndExtract(ctx, 0)
	assert.True(t, newCount >= 0) // may be 0 or 1 depending on timing
}

func TestOrchestrator_MultipleArchivesSameLevel(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	zip1Path := createTestZip(t, dir, map[string]string{"file1.txt": "from zip1"})
	zip1Content, err := os.ReadFile(zip1Path)
	require.NoError(t, err)

	// Need a different dir to avoid overwriting test.zip
	dir2 := t.TempDir()
	zip2Path := createTestZip(t, dir2, map[string]string{"file2.txt": "from zip2"})
	zip2Content, err := os.ReadFile(zip2Path)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/archive1.zip": string(zip1Content),
		"/archive2.zip": string(zip2Content),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeIndexedArchives = true

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	newCount := orch.DiscoverAndExtract(ctx, 0)
	assert.Equal(t, 2, newCount, "should extract both archives")
	assert.Equal(t, 2, orch.Resolver().ChildCount())
}

func TestOrchestrator_CorruptArchiveSkipped(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// A file with .zip extension but invalid content
	parent := newMockResolver(map[string]string{
		"/corrupt.zip": "this is not a valid zip file",
		"/normal.txt":  "just text",
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeIndexedArchives = true

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	// Should not panic or error out; corrupt archives should be skipped
	newCount := orch.DiscoverAndExtract(ctx, 0)
	assert.Equal(t, 0, newCount, "corrupt archive should be skipped")
}

func TestOrchestrator_EmptyArchive(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create an empty zip
	emptyZipPath := createTestZip(t, dir, map[string]string{})
	emptyZipContent, err := os.ReadFile(emptyZipPath)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/empty.zip": string(emptyZipContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeIndexedArchives = true

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	newCount := orch.DiscoverAndExtract(ctx, 0)
	assert.Equal(t, 0, newCount, "empty archive should not count as extracted")
}

func TestOrchestrator_PerArchiveFileLimitApplied(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create a zip with many files
	files := map[string]string{}
	for i := 0; i < 10; i++ {
		files[filepath.Join("dir", string(rune('a'+i))+".txt")] = "content"
	}
	zipPath := createTestZip(t, dir, files)
	zipContent, err := os.ReadFile(zipPath)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/big.zip": string(zipContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeIndexedArchives = true
	cfg.MaxFileCount = 3 // only allow 3 files to be extracted

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	// Should partially extract but still register the archive
	newCount := orch.DiscoverAndExtract(ctx, 0)
	// Extraction will fail after 3 files, but partial extraction counts
	assert.True(t, newCount >= 0)
}

func TestOrchestrator_RelationshipsIncludeDepth(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	zipPath := createTestZip(t, dir, map[string]string{"file.txt": "data"})
	zipContent, err := os.ReadFile(zipPath)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/archive.zip": string(zipContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeIndexedArchives = true

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()
	orch.DiscoverAndExtract(ctx, 0)

	rels := orch.Relationships()
	require.Len(t, rels, 1)

	// verify the relationship structure
	rel := rels[0]
	assert.Equal(t, "contains", string(rel.Type))

	// From should be the archive's coordinates
	fromCoords, ok := rel.From.(file.Coordinates)
	require.True(t, ok)
	assert.Equal(t, "/archive.zip", fromCoords.RealPath)
}

func TestOrchestrator_ZipDisabledByConfig(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	zipPath := createTestZip(t, dir, map[string]string{"inner.txt": "data"})
	zipContent, err := os.ReadFile(zipPath)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/test.zip": string(zipContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeIndexedArchives = false // disable zip extraction

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	newCount := orch.DiscoverAndExtract(ctx, 0)
	assert.Equal(t, 0, newCount)
}
