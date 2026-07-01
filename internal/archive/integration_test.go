package archive

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cataloging"
)

// TestIntegration_TarGzContainingPythonPackage tests the scenario where a tar.gz
// archive contains Python package metadata files that would normally be found by
// the Python cataloger. This verifies the orchestrator makes those files visible.
func TestIntegration_TarGzContainingPythonPackage(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create a tar.gz containing Python dist-info metadata
	tarPath := filepath.Join(dir, "python-packages.tar.gz")
	createTarGzWithFiles(t, tarPath, map[string]string{
		"lib/python3.9/site-packages/requests-2.28.0.dist-info/METADATA": `Metadata-Version: 2.1
Name: requests
Version: 2.28.0
Summary: Python HTTP for Humans.
`,
		"lib/python3.9/site-packages/requests-2.28.0.dist-info/RECORD": "requests/__init__.py,sha256=abc,1234",
		"lib/python3.9/site-packages/requests/__init__.py":              "# requests library",
	})
	tarContent, err := os.ReadFile(tarPath)
	require.NoError(t, err)

	// Base resolver sees the tar.gz as a single opaque file
	parent := newMockResolver(map[string]string{
		"/app/python-packages.tar.gz": string(tarContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeUnindexedArchives = true

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	// Extract the archive
	count := orch.DiscoverAndExtract(ctx, 0)
	require.Equal(t, 1, count, "should extract the tar.gz")

	// The Python METADATA file should now be visible through the composite resolver
	resolver := orch.Resolver()
	locs, err := resolver.FilesByPath("/lib/python3.9/site-packages/requests-2.28.0.dist-info/METADATA")
	require.NoError(t, err)
	require.Len(t, locs, 1, "METADATA file should be visible through the composite resolver")

	// Verify the access path shows it came from the archive
	assert.Contains(t, locs[0].AccessPath, "python-packages.tar.gz:")
	assert.Contains(t, locs[0].AccessPath, "METADATA")

	// Verify we can read the content
	reader, err := resolver.FileContentsByLocation(locs[0])
	require.NoError(t, err)
	defer reader.Close()

	buf := make([]byte, 1024)
	n, _ := reader.Read(buf)
	assert.Contains(t, string(buf[:n]), "Name: requests")
}

// TestIntegration_ZipContainingJar tests a zip archive containing a JAR file,
// which itself should be extractable in a second round.
func TestIntegration_ZipContainingJar(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create an inner JAR (which is just a zip) with a MANIFEST.MF
	innerJarPath := filepath.Join(dir, "inner.jar")
	createZipWithFiles(t, innerJarPath, map[string]string{
		"META-INF/MANIFEST.MF": `Manifest-Version: 1.0
Implementation-Title: example-lib
Implementation-Version: 1.2.3
`,
	})
	innerJarContent, err := os.ReadFile(innerJarPath)
	require.NoError(t, err)

	// Create an outer zip containing the JAR and other files
	outerZipPath := filepath.Join(dir, "app-bundle.zip")
	createZipWithFiles(t, outerZipPath, map[string]string{
		"lib/example-lib-1.2.3.jar": string(innerJarContent),
		"README.md":                 "# Application Bundle",
	})
	outerZipContent, err := os.ReadFile(outerZipPath)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/downloads/app-bundle.zip": string(outerZipContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 2
	cfg.IncludeIndexedArchives = true

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	// Round 1: extract outer zip
	count1 := orch.DiscoverAndExtract(ctx, 0)
	require.Equal(t, 1, count1, "should extract outer zip")

	// Round 2: extract inner JAR found inside the zip
	count2 := orch.DiscoverAndExtract(ctx, 1)
	require.Equal(t, 1, count2, "should extract inner JAR")

	resolver := orch.Resolver()

	// The MANIFEST.MF from inside the JAR should be visible
	locs, err := resolver.FilesByPath("/META-INF/MANIFEST.MF")
	require.NoError(t, err)
	require.Len(t, locs, 1, "MANIFEST.MF should be visible from nested JAR")

	// The access path should show the full nesting chain
	accessPath := locs[0].AccessPath
	assert.Contains(t, accessPath, "app-bundle.zip:")
	assert.Contains(t, accessPath, "example-lib-1.2.3.jar:")
	assert.Contains(t, accessPath, "MANIFEST.MF")

	// Verify relationships
	rels := orch.Relationships()
	assert.Len(t, rels, 2, "should have relationships for both extracted archives")
}

// TestIntegration_MixedArchiveTypes tests a directory containing both
// zip and tar.gz archives that should be extracted in a single round.
func TestIntegration_MixedArchiveTypes(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create a zip
	zipPath := createTestZip(t, dir, map[string]string{
		"from-zip.txt": "zip content",
	})
	zipContent, err := os.ReadFile(zipPath)
	require.NoError(t, err)

	// Create a tar.gz
	tarPath := createTestTarGz(t, dir, map[string]string{
		"from-tar.txt": "tar content",
	})
	tarContent, err := os.ReadFile(tarPath)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/data/archive.zip":    string(zipContent),
		"/data/archive.tar.gz": string(tarContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeIndexedArchives = true
	cfg.IncludeUnindexedArchives = true

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	count := orch.DiscoverAndExtract(ctx, 0)
	assert.Equal(t, 2, count, "should extract both archives")

	resolver := orch.Resolver()

	// Both files should be visible
	zipLocs, err := resolver.FilesByPath("/from-zip.txt")
	require.NoError(t, err)
	assert.Len(t, zipLocs, 1, "file from zip should be visible")

	tarLocs, err := resolver.FilesByPath("/from-tar.txt")
	require.NoError(t, err)
	assert.Len(t, tarLocs, 1, "file from tar should be visible")
}

// TestIntegration_DepthLimitPreventsDeepExtraction verifies that the
// depth limit correctly stops extraction at the configured level.
func TestIntegration_DepthLimitPreventsDeepExtraction(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create a deeply nested archive: zip -> zip -> zip -> file
	innermostDir := filepath.Join(dir, "inner")
	require.NoError(t, os.MkdirAll(innermostDir, 0o755))
	innermost := createTestZip(t, innermostDir, map[string]string{
		"secret.txt": "you found me!",
	})
	innermostContent, err := os.ReadFile(innermost)
	require.NoError(t, err)

	middleDir := filepath.Join(dir, "middle")
	require.NoError(t, os.MkdirAll(middleDir, 0o755))
	middle := createTestZip(t, middleDir, map[string]string{
		"innermost.zip": string(innermostContent),
	})
	middleContent, err := os.ReadFile(middle)
	require.NoError(t, err)

	outerDir := filepath.Join(dir, "outer")
	require.NoError(t, os.MkdirAll(outerDir, 0o755))
	outerZip := createTestZip(t, outerDir, map[string]string{
		"middle.zip": string(middleContent),
	})
	outerContent, err := os.ReadFile(outerZip)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/nested.zip": string(outerContent),
	})

	// Only allow depth 1 — should only extract the outer zip
	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeIndexedArchives = true

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	count := orch.DiscoverAndExtract(ctx, 0)
	assert.Equal(t, 1, count, "should only extract the outer zip")

	// middle.zip should be visible but secret.txt should NOT be
	resolver := orch.Resolver()

	middleLocs, err := resolver.FilesByPath("/middle.zip")
	require.NoError(t, err)
	assert.Len(t, middleLocs, 1, "middle.zip should be visible at depth 1")

	secretLocs, err := resolver.FilesByPath("/secret.txt")
	require.NoError(t, err)
	assert.Len(t, secretLocs, 0, "secret.txt should NOT be visible (depth limit)")
}

// TestIntegration_ExcludeExtensionPreventsExtraction verifies that
// excluded extensions are respected.
func TestIntegration_ExcludeExtensionPreventsExtraction(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	zipPath := createTestZip(t, dir, map[string]string{
		"data.txt": "from zip",
	})
	zipContent, err := os.ReadFile(zipPath)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/archive.zip": string(zipContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 1
	cfg.IncludeIndexedArchives = true
	cfg.ExcludeExtensions = []string{".zip"} // exclude zip files

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	count := orch.DiscoverAndExtract(ctx, 0)
	assert.Equal(t, 0, count, "zip should be excluded by extension")
}

// TestIntegration_MultiLevelMixedFormats tests a 3-level nesting chain with
// different archive formats: tar.gz -> zip -> tar.gz -> files.
// This is the most realistic cross-format recursive extraction scenario.
func TestIntegration_MultiLevelMixedFormats(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Level 3 (deepest): a tar.gz containing application files
	level3Dir := filepath.Join(dir, "level3")
	require.NoError(t, os.MkdirAll(level3Dir, 0o755))
	level3Path := filepath.Join(level3Dir, "app-data.tar.gz")
	createTarGzWithFiles(t, level3Path, map[string]string{
		"config.yaml": "app: myapp\nversion: 1.0",
		"bin/run.sh":  "#!/bin/sh\necho hello",
	})
	level3Content, err := os.ReadFile(level3Path)
	require.NoError(t, err)

	// Level 2: a zip containing the level3 tar.gz and some metadata
	level2Dir := filepath.Join(dir, "level2")
	require.NoError(t, os.MkdirAll(level2Dir, 0o755))
	level2Path := filepath.Join(level2Dir, "package.zip")
	createZipWithFiles(t, level2Path, map[string]string{
		"app-data.tar.gz":   string(level3Content),
		"package-info.json": `{"name": "mypackage", "version": "2.0"}`,
	})
	level2Content, err := os.ReadFile(level2Path)
	require.NoError(t, err)

	// Level 1 (outermost): a tar.gz containing the level2 zip
	level1Dir := filepath.Join(dir, "level1")
	require.NoError(t, os.MkdirAll(level1Dir, 0o755))
	level1Path := filepath.Join(level1Dir, "distribution.tar.gz")
	createTarGzWithFiles(t, level1Path, map[string]string{
		"package.zip": string(level2Content),
		"LICENSE":     "MIT License",
	})
	level1Content, err := os.ReadFile(level1Path)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/distribution.tar.gz": string(level1Content),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 3
	cfg.IncludeIndexedArchives = true
	cfg.IncludeUnindexedArchives = true

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	// Round 1: extract distribution.tar.gz
	count1 := orch.DiscoverAndExtract(ctx, 0)
	require.Equal(t, 1, count1, "round 1: should extract distribution.tar.gz")

	// Round 2: extract package.zip from inside distribution.tar.gz
	count2 := orch.DiscoverAndExtract(ctx, 1)
	require.Equal(t, 1, count2, "round 2: should extract package.zip")

	// Round 3: extract app-data.tar.gz from inside package.zip
	count3 := orch.DiscoverAndExtract(ctx, 2)
	require.Equal(t, 1, count3, "round 3: should extract app-data.tar.gz")

	resolver := orch.Resolver()

	// Verify files from all levels are accessible:

	// Level 1: LICENSE from distribution.tar.gz
	locs, err := resolver.FilesByPath("/LICENSE")
	require.NoError(t, err)
	require.Len(t, locs, 1, "LICENSE from level 1 should be visible")
	assert.Contains(t, locs[0].AccessPath, "distribution.tar.gz:")

	// Level 2: package-info.json from package.zip
	locs, err = resolver.FilesByPath("/package-info.json")
	require.NoError(t, err)
	require.Len(t, locs, 1, "package-info.json from level 2 should be visible")
	assert.Contains(t, locs[0].AccessPath, "package.zip:")

	// Level 3: config.yaml from app-data.tar.gz
	locs, err = resolver.FilesByPath("/config.yaml")
	require.NoError(t, err)
	require.Len(t, locs, 1, "config.yaml from level 3 should be visible")
	assert.Contains(t, locs[0].AccessPath, "app-data.tar.gz:")

	// Level 3: bin/run.sh from app-data.tar.gz
	locs, err = resolver.FilesByPath("/bin/run.sh")
	require.NoError(t, err)
	require.Len(t, locs, 1, "bin/run.sh from level 3 should be visible")

	// Verify we can read deeply nested content
	reader, err := resolver.FileContentsByLocation(locs[0])
	require.NoError(t, err)
	defer reader.Close()
	buf := make([]byte, 1024)
	n, _ := reader.Read(buf)
	assert.Contains(t, string(buf[:n]), "echo hello")

	// Verify relationships cover all 3 levels
	rels := orch.Relationships()
	assert.Len(t, rels, 3, "should have 3 relationships (one per extracted archive)")
}

// TestIntegration_TarInsideZipInsideTar tests tar -> zip -> tar nesting
// (the reverse of the above test), ensuring bidirectional format crossing.
func TestIntegration_TarInsideZipInsideTar(t *testing.T) {
	dir := t.TempDir()
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Innermost: a tar.gz with a single file
	innerTarDir := filepath.Join(dir, "innertar")
	require.NoError(t, os.MkdirAll(innerTarDir, 0o755))
	innerTarPath := filepath.Join(innerTarDir, "inner.tar.gz")
	createTarGzWithFiles(t, innerTarPath, map[string]string{
		"deeply-nested.txt": "found at the bottom",
	})
	innerTarContent, err := os.ReadFile(innerTarPath)
	require.NoError(t, err)

	// Middle: a zip containing the inner tar
	middleZipDir := filepath.Join(dir, "middlezip")
	require.NoError(t, os.MkdirAll(middleZipDir, 0o755))
	middleZipPath := filepath.Join(middleZipDir, "middle.zip")
	createZipWithFiles(t, middleZipPath, map[string]string{
		"inner.tar.gz": string(innerTarContent),
		"middle.txt":   "middle level",
	})
	middleZipContent, err := os.ReadFile(middleZipPath)
	require.NoError(t, err)

	// Outermost: a tar.gz containing the middle zip
	outerTarDir := filepath.Join(dir, "outertar")
	require.NoError(t, os.MkdirAll(outerTarDir, 0o755))
	outerTarPath := filepath.Join(outerTarDir, "outer.tar.gz")
	createTarGzWithFiles(t, outerTarPath, map[string]string{
		"middle.zip": string(middleZipContent),
		"outer.txt":  "outer level",
	})
	outerTarContent, err := os.ReadFile(outerTarPath)
	require.NoError(t, err)

	parent := newMockResolver(map[string]string{
		"/outer.tar.gz": string(outerTarContent),
	})

	cfg := cataloging.DefaultArchiveSearchConfig()
	cfg.MaxDepth = 3
	cfg.IncludeIndexedArchives = true
	cfg.IncludeUnindexedArchives = true

	orch := NewOrchestrator(parent, cfg, tmpDir, testResolverFactory)
	defer orch.Cleanup()

	// Extract all 3 levels
	count1 := orch.DiscoverAndExtract(ctx, 0)
	require.Equal(t, 1, count1)
	count2 := orch.DiscoverAndExtract(ctx, 1)
	require.Equal(t, 1, count2)
	count3 := orch.DiscoverAndExtract(ctx, 2)
	require.Equal(t, 1, count3)

	resolver := orch.Resolver()

	// Check all levels are accessible
	outerLocs, err := resolver.FilesByPath("/outer.txt")
	require.NoError(t, err)
	require.Len(t, outerLocs, 1)

	middleLocs, err := resolver.FilesByPath("/middle.txt")
	require.NoError(t, err)
	require.Len(t, middleLocs, 1)

	deepLocs, err := resolver.FilesByPath("/deeply-nested.txt")
	require.NoError(t, err)
	require.Len(t, deepLocs, 1)

	// Read the deeply nested content
	reader, err := resolver.FileContentsByLocation(deepLocs[0])
	require.NoError(t, err)
	defer reader.Close()
	buf := make([]byte, 1024)
	n, _ := reader.Read(buf)
	assert.Equal(t, "found at the bottom", string(buf[:n]))

	// The access path should show the full chain: tar -> zip -> tar -> file
	accessPath := deepLocs[0].AccessPath
	assert.Contains(t, accessPath, "outer.tar.gz:")
	assert.Contains(t, accessPath, "middle.zip:")
	assert.Contains(t, accessPath, "inner.tar.gz:")
	assert.Contains(t, accessPath, "deeply-nested.txt")
}

// createZipWithFiles creates a zip at the given path with the given files.
func createZipWithFiles(t *testing.T, zipPath string, files map[string]string) {
	t.Helper()
	f, err := os.Create(zipPath)
	require.NoError(t, err)
	defer f.Close()

	w := zip.NewWriter(f)
	for name, content := range files {
		fw, err := w.Create(name)
		require.NoError(t, err)
		_, err = fw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
}

// createTarGzWithFiles creates a tar.gz at the given path with the given files.
func createTarGzWithFiles(t *testing.T, tarPath string, files map[string]string) {
	t.Helper()
	f, err := os.Create(tarPath)
	require.NoError(t, err)
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	// sort keys for deterministic output
	for name, content := range files {
		// create parent dirs as needed
		dir := filepath.Dir(name)
		if dir != "." {
			hdr := &tar.Header{
				Typeflag: tar.TypeDir,
				Name:     dir + "/",
				Mode:     0o755,
			}
			require.NoError(t, tw.WriteHeader(hdr))
		}

		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err = tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
}

