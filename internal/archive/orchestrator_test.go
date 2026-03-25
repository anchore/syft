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
