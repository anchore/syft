package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunSplit_BasicExecution(t *testing.T) {
	// use the example SBOM
	sbomPath := "../../../../examples/decode_sbom/alpine.syft.json"
	if _, err := os.Stat(sbomPath); os.IsNotExist(err) {
		t.Skip("example SBOM not found, skipping integration test")
	}

	// create temporary output directory
	tmpDir, err := os.MkdirTemp("", "syft-split-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	opts := &SplitOptions{
		Packages:  []string{"alpine-baselayout"},
		OutputDir: tmpDir,
		Drop:      []string{},
	}

	err = RunSplit(opts, sbomPath)
	require.NoError(t, err)

	// verify output files were created
	entries, err := os.ReadDir(tmpDir)
	require.NoError(t, err)
	assert.NotEmpty(t, entries, "expected at least one output file")

	// verify output file is valid JSON
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(tmpDir, entry.Name()))
		require.NoError(t, err)
		assert.NotEmpty(t, content)
		// basic JSON validation - should start with {
		assert.True(t, len(content) > 0 && content[0] == '{', "output should be valid JSON")
	}
}

func TestRunSplit_InvalidDropOption(t *testing.T) {
	opts := &SplitOptions{
		Packages:  []string{"test"},
		OutputDir: ".",
		Drop:      []string{"invalid-option"},
	}

	err := RunSplit(opts, "some-sbom.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid drop option")
}

func TestRunSplit_NoMatchingPackages(t *testing.T) {
	sbomPath := "../../../../examples/decode_sbom/alpine.syft.json"
	if _, err := os.Stat(sbomPath); os.IsNotExist(err) {
		t.Skip("example SBOM not found, skipping integration test")
	}

	tmpDir, err := os.MkdirTemp("", "syft-split-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	opts := &SplitOptions{
		Packages:  []string{"nonexistent-package-xyz"},
		OutputDir: tmpDir,
		Drop:      []string{},
	}

	err = RunSplit(opts, sbomPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no packages matched")
}

func TestRunSplit_WithDropOptions(t *testing.T) {
	sbomPath := "../../../../examples/decode_sbom/alpine.syft.json"
	if _, err := os.Stat(sbomPath); os.IsNotExist(err) {
		t.Skip("example SBOM not found, skipping integration test")
	}

	tmpDir, err := os.MkdirTemp("", "syft-split-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	opts := &SplitOptions{
		Packages:  []string{"alpine-baselayout"},
		OutputDir: tmpDir,
		Drop:      []string{"source", "location:fsid"},
	}

	err = RunSplit(opts, sbomPath)
	require.NoError(t, err)

	// verify output file was created
	entries, err := os.ReadDir(tmpDir)
	require.NoError(t, err)
	assert.NotEmpty(t, entries)
}

func TestRunSplit_FileNotFound(t *testing.T) {
	opts := &SplitOptions{
		Packages:  []string{"test"},
		OutputDir: ".",
		Drop:      []string{},
	}

	err := RunSplit(opts, "/nonexistent/path/sbom.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open SBOM file")
}
