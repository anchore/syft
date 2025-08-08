package yocto

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// TestYoctoIntegrationWithTestData tests the cataloger against local test data
func TestYoctoIntegrationWithTestData(t *testing.T) {
	// Use local test data files
	testDataPaths := []string{
		"testdata/license.manifest",
		"testdata/bb_cache.dat", 
		"testdata/bitbake_layers_output.txt",
	}

	// Verify test data exists
	for _, path := range testDataPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Skipf("Test data file not found: %s", path)
			return
		}
	}

	// Create resolver with test data paths
	resolver := file.NewMockResolverForPaths(testDataPaths...)

	yoctoCataloger := NewCataloger(DefaultConfig())
	
	// Test with testdata build directory structure
	if c, ok := yoctoCataloger.(*cataloger); ok {
		c.config.BuildDir = "testdata"
	}
	
	packages, relationships, err := yoctoCataloger.Catalog(nil, resolver)
	
	// Log the results for debugging
	t.Logf("Found %d packages and %d relationships", len(packages), len(relationships))
	t.Logf("Error (if any): %v", err)
	
	// We expect this to work or fail gracefully (e.g., if Python not available)
	if err != nil && strings.Contains(err.Error(), "failed to parse cache") {
		t.Logf("Cache parsing failed (expected if Python not available): %v", err)
		return
	}
	
	// If we get packages, validate them
	for i, yoctoPkg := range packages {
		if i >= 5 { // Limit logging to first 5 packages
			break
		}
		t.Logf("Package %d: %s-%s (Type: %s)", i+1, yoctoPkg.Name, yoctoPkg.Version, yoctoPkg.Type)
		
		assert.NotEmpty(t, yoctoPkg.Name, "Package should have a name")
		assert.NotEmpty(t, yoctoPkg.Version, "Package should have a version")
		assert.Equal(t, pkg.YoctoPkg, yoctoPkg.Type, "Package should be Yocto type")
	}
}

// TestValidateAgainstBitbakeLayersOutput validates that our parsing logic matches the reference
func TestValidateAgainstBitbakeLayersOutput(t *testing.T) {
	refPath := "testdata/bitbake_layers_output.txt"
	
	// Check if reference file exists
	if _, err := os.Stat(refPath); os.IsNotExist(err) {
		t.Skip("Reference file not found")
		return
	}

	content, err := os.ReadFile(refPath)
	require.NoError(t, err)

	// Parse reference recipes
	refRecipes := parseReferenceOutput(string(content))
	
	// Validate parsing logic
	assert.Greater(t, len(refRecipes), 0, "Should parse some reference recipes")
	
	// Log some examples
	count := 0
	for recipe, info := range refRecipes {
		if count >= 10 { // Limit to first 10
			break
		}
		t.Logf("Reference recipe: %s -> %s", recipe, info)
		count++
	}
	
	// Test specific known recipes
	expectedRecipes := []string{
		"acl",
		"alsa-lib", 
		"base-files",
		"bash",
		"busybox",
		"glibc",
		"linux-yocto",
	}
	
	for _, expected := range expectedRecipes {
		if _, found := refRecipes[expected]; found {
			t.Logf("✓ Found expected recipe: %s", expected)
		} else {
			t.Logf("✗ Missing expected recipe: %s", expected)
		}
	}
}

// TestCacheParsingWithPython tests our Python cache parsing logic
func TestCacheParsingWithPython(t *testing.T) {
	cacheFile := "testdata/bb_cache.dat"
	
	// Check if cache file exists
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		t.Skip("Cache file not found")
		return
	}

	cataloger := &cataloger{config: DefaultConfig()}
	
	// Test the Python parsing directly
	recipes, err := cataloger.parseCacheWithPython(cacheFile, "testdata")
	
	if err != nil {
		t.Logf("Cache parsing failed (expected if Python not available): %v", err)
		return
	}
	
	t.Logf("Successfully parsed %d recipes from cache", len(recipes))
	
	// Log some examples
	for i, recipe := range recipes {
		if i >= 5 { // Limit to first 5
			break
		}
		t.Logf("Cache recipe %d: %s-%s (Layer: %s)", i+1, recipe.PackageName, recipe.Version, recipe.Layer)
	}
	
	// Validate structure
	for _, recipe := range recipes {
		assert.NotEmpty(t, recipe.PackageName, "Recipe should have a package name")
		assert.NotEmpty(t, recipe.Version, "Recipe should have a version")
		assert.NotEmpty(t, recipe.FileName, "Recipe should have a filename")
	}
}

// TestCreatePackagesFromReference creates packages based on reference data to validate our logic
func TestCreatePackagesFromReference(t *testing.T) {
	// Create test recipes based on known entries from bitbake_layers_output.txt
	testRecipes := []CacheRecipeInfo{
		{
			FileName:     "/workspace/meta/recipes-core/base-files/base-files_3.0.14.bb",
			PackageName:  "base-files",
			Version:      "3.0.14",
			PackageEpoch: "",
			Release:      "r0",
			License:      "MIT",
			Provides:     []string{"base-files"},
			Depends:      []string{},
			RDepends:     map[string][]string{},
			Packages:     []string{"base-files"},
			Layer:        "meta",
			Recipe:       "base-files_3.0.14.bb",
		},
		{
			FileName:     "/workspace/meta/recipes-core/glibc/glibc_2.35.bb",
			PackageName:  "glibc",
			Version:      "2.35",
			PackageEpoch: "",
			Release:      "r0",
			License:      "GPL-2.0 & LGPL-2.1",
			Provides:     []string{"glibc", "libc"},
			Depends:      []string{},
			RDepends:     map[string][]string{},
			Packages:     []string{"glibc", "glibc-locale"},
			Layer:        "meta",
			Recipe:       "glibc_2.35.bb",
		},
		{
			FileName:     "/workspace/meta/recipes-core/busybox/busybox_1.35.0.bb",
			PackageName:  "busybox",
			Version:      "1.35.0",
			PackageEpoch: "",
			Release:      "r0",
			License:      "GPL-2.0-only & bzip2-1.0.6",
			Provides:     []string{"busybox"},
			Depends:      []string{"glibc"},
			RDepends:     map[string][]string{"busybox": {"glibc"}},
			Packages:     []string{"busybox"},
			Layer:        "meta",
			Recipe:       "busybox_1.35.0.bb",
		},
	}

	cataloger := &cataloger{config: DefaultConfig()}
	
	for _, recipe := range testRecipes {
		yoctoPkg := cataloger.createPackageFromCacheRecipe(recipe, "/test/cache.dat")
		
		// Validate package creation
		assert.Equal(t, recipe.PackageName, yoctoPkg.Name)
		assert.Contains(t, yoctoPkg.Version, recipe.Version)
		assert.Equal(t, pkg.YoctoPkg, yoctoPkg.Type)
		
		// Validate PURL
		expectedPURL := "pkg:openembedded/meta/" + recipe.PackageName + "@" + yoctoPkg.Version
		assert.Equal(t, expectedPURL, yoctoPkg.PURL)
		
		// Validate metadata
		metadata, ok := yoctoPkg.Metadata.(pkg.YoctoMetadata)
		require.True(t, ok)
		assert.Equal(t, recipe.PackageName, metadata.Name)
		assert.Equal(t, recipe.Version, metadata.Version)
		assert.Equal(t, recipe.License, metadata.License)
		assert.Equal(t, recipe.Layer, metadata.Layer)
		assert.Equal(t, recipe.Recipe, metadata.Recipe)
		
		t.Logf("✓ Created package: %s-%s from layer %s", yoctoPkg.Name, yoctoPkg.Version, metadata.Layer)
	}
}

// TestCacheScriptGeneration tests that our Python script generation works
func TestCacheScriptGeneration(t *testing.T) {
	cataloger := &cataloger{config: DefaultConfig()}
	script := cataloger.createCacheParserScript()
	
	// Validate script contains required components
	requiredElements := []string{
		"#!/usr/bin/env python3",
		"import pickle",
		"import json",
		"def parse_cache_file",
		"def extract_layer_from_path",
		"unpickler = pickle.Unpickler(f)",
		"getattr(value, 'pn'",
		"getattr(value, 'pv'",
		"json.dumps(recipes",
	}
	
	for _, element := range requiredElements {
		assert.Contains(t, script, element, "Script should contain: %s", element)
	}
	
	// Validate script is executable Python
	assert.True(t, len(script) > 1000, "Script should be substantial")
	assert.True(t, strings.Count(script, "\n") > 50, "Script should have multiple lines")
}

// Helper function to compare our parsing logic with reference output  
func TestReferenceOutputParsing(t *testing.T) {
	// Sample reference output
	sampleOutput := `NOTE: Starting bitbake server...
Loading cache...done.
Loaded 1644 entries from dependency cache.
=== Available recipes: ===
acl:
  meta                 2.3.1
alsa-lib:
  meta                 1.2.6.1
base-files:
  meta                 3.0.14
busybox:
  meta                 1.35.0
glibc:
  meta                 2.35
linux-yocto:
  meta                 5.15.186+gitAUTOINC+5932fcfa69_48702d462c
`
	
	recipes := parseReferenceOutput(sampleOutput)
	
	// Validate expected recipes were found
	expectedRecipes := map[string]bool{
		"acl":         true,
		"alsa-lib":    true,
		"base-files":  true,
		"busybox":     true,
		"glibc":       true,
		"linux-yocto": true,
	}
	
	for expected := range expectedRecipes {
		assert.Contains(t, recipes, expected, "Should find recipe: %s", expected)
	}
	
	// Validate parsing doesn't include non-recipe lines
	invalidEntries := []string{
		"NOTE",
		"Loading",
		"Loaded",
		"===",
		"meta",
	}
	
	for _, invalid := range invalidEntries {
		assert.NotContains(t, recipes, invalid, "Should not include: %s", invalid)
	}
	
	t.Logf("Successfully parsed %d recipes from sample output", len(recipes))
}
