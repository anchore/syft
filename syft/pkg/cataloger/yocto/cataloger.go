/*
Package yocto provides a concrete Cataloger implementation for Yocto/OpenEmbedded build systems.

This cataloger analyzes Yocto build artifacts and cache files to extract package information.
It supports parsing both license.manifest files and BitBake cache files (bb_cache.dat).

For BitBake cache parsing, the cataloger:
1. Attempts to use actual BitBake libraries when available for full compatibility
2. Falls back to basic parsing when BitBake libraries are not accessible
3. Supports configuration via environment variables or config options:
  - BITBAKE_HOME: Path to BitBake installation directory
  - BITBAKE_LIB: Path to BitBake library directory
  - Config.BitBakeHome: Configuration option for BitBake home directory
  - Config.BitBakeLib: Configuration option for BitBake library directory

The cataloger automatically detects BitBake installations in common locations including:
- workspace/bitbake/lib (relative to build directory)
- System installations (/usr/lib/python3/dist-packages)
- Local installations (/usr/local/lib/python3/dist-packages)
- Yocto installations (/opt/yocto/bitbake/lib)
*/
package yocto

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const catalogerName = "yocto-cataloger"

type Config struct {
	BuildDir    string `yaml:"build-dir" json:"build-dir" mapstructure:"build-dir"`
	BitBakeHome string `yaml:"bitbake-home" json:"bitbake-home" mapstructure:"bitbake-home"`
	BitBakeLib  string `yaml:"bitbake-lib" json:"bitbake-lib" mapstructure:"bitbake-lib"`
}

// CacheRecipeInfo represents recipe information extracted from BitBake cache
type CacheRecipeInfo struct {
	FileName     string            `json:"filename"`
	PackageName  string            `json:"pn"`
	Version      string            `json:"pv"`
	PackageEpoch string            `json:"pe"`
	Release      string            `json:"pr"`
	License      string            `json:"license"`
	Provides     []string          `json:"provides"`
	Depends      []string          `json:"depends"`
	RDepends     map[string][]string `json:"rdepends"`
	Packages     []string          `json:"packages"`
	Layer        string            `json:"layer"`
	Recipe       string            `json:"recipe"`
}

func DefaultConfig() Config {
	return Config{
		BuildDir:    "build",
		BitBakeHome: "",
		BitBakeLib:  "",
	}
}

type cataloger struct {
	config Config
}

// NewCataloger returns a new cataloger for Yocto/OpenEmbedded projects.
func NewCataloger(cfg Config) pkg.Cataloger {
	return &cataloger{
		config: cfg,
	}
}

// Name returns a string that uniquely describes the cataloger
func (c cataloger) Name() string {
	return catalogerName
}

// Catalog discovers packages by analyzing Yocto build artifacts
func (c cataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship

	log.WithFields("name", catalogerName).Trace("starting cataloging")

	// Check if this is a Yocto build directory
	buildDir := c.detectYoctoBuildDir(resolver)
	if buildDir == "" {
		return packages, relationships, nil
	}

	// Try to parse license.manifest file
	licenseManifest := c.findLicenseManifest(resolver, buildDir)
	if licenseManifest != "" {
		pkgs, rels, err := c.parseManifestFile(resolver, licenseManifest)
		if err != nil {
			return packages, relationships, fmt.Errorf("failed to parse license manifest: %w", err)
		}
		packages = append(packages, pkgs...)
		relationships = append(relationships, rels...)
	}

	// Try to parse bitbake cache for additional recipes
	cachePkgs, cacheRels, err := c.parseBitbakeCache(resolver, buildDir)
	if err == nil {
		packages = append(packages, cachePkgs...)
		relationships = append(relationships, cacheRels...)
	}

	return packages, relationships, nil
}

// detectYoctoBuildDir checks if the given path contains Yocto build artifacts
// TODO: Need to improve this to be more robust and handle more cases.
func (c cataloger) detectYoctoBuildDir(resolver file.Resolver) string {
	log.WithFields("cataloger", catalogerName).Debug("starting Yocto build directory detection")
	
	// Look for typical Yocto build directory structure
	yoctoIndicators := []string{
		"conf/bblayers.conf",
		"conf/local.conf",
		"tmp/cache",
		"tmp/deploy",
	}
	
	log.WithFields("cataloger", catalogerName).Debugf("looking for Yocto indicators: %v", yoctoIndicators)

	// Check if build directory is specified in config
	if c.config.BuildDir != "" {
		log.WithFields("cataloger", catalogerName).Debugf("checking configured build directory: %s", c.config.BuildDir)
		foundIndicators := 0
		for _, indicator := range yoctoIndicators {
			testPath := filepath.Join(c.config.BuildDir, indicator)
			log.WithFields("cataloger", catalogerName).Tracef("checking for indicator: %s", testPath)
			if locations, err := resolver.FilesByPath(testPath); err == nil && len(locations) > 0 {
				var foundPaths []string
				for _, loc := range locations {
					foundPaths = append(foundPaths, loc.RealPath)
				}
				log.WithFields("cataloger", catalogerName).Debugf("found indicator in configured build dir: %s (locations: %v)", testPath, foundPaths)
				foundIndicators++
			} else {
				if err != nil {
					log.WithFields("cataloger", catalogerName).Tracef("indicator not found: %s (error: %v)", testPath, err)
				} else {
					log.WithFields("cataloger", catalogerName).Tracef("indicator not found: %s (no matching locations)", testPath)
				}
			}
		}
		if foundIndicators > 0 {
			log.WithFields("cataloger", catalogerName).Infof("using configured build directory %s (found %d/%d indicators)", c.config.BuildDir, foundIndicators, len(yoctoIndicators))
			return c.config.BuildDir
		} else {
			log.WithFields("cataloger", catalogerName).Warnf("configured build directory %s does not contain any Yocto indicators", c.config.BuildDir)
		}
	}

	// Look for build directory in common locations
	commonBuildDirs := []string{
		"build",
		"poky/build", 
		"yocto/build",
		".",
	}
	
	log.WithFields("cataloger", catalogerName).Debugf("searching for build directory in common locations: %v", commonBuildDirs)

	for _, buildDir := range commonBuildDirs {
		log.WithFields("cataloger", catalogerName).Debugf("checking build directory candidate: %s", buildDir)
		hasIndicators := 0
		var foundIndicators []string
		var missingIndicators []string
		
		for _, indicator := range yoctoIndicators {
			testPath := filepath.Join(buildDir, indicator)
			log.WithFields("cataloger", catalogerName).Tracef("checking for indicator: %s", testPath)
			if locations, err := resolver.FilesByPath(testPath); err == nil && len(locations) > 0 {
				hasIndicators++
				foundIndicators = append(foundIndicators, indicator)
				var foundPaths []string
				for _, loc := range locations {
					foundPaths = append(foundPaths, loc.RealPath)
				}
				log.WithFields("cataloger", catalogerName).Tracef("found indicator: %s (locations: %v)", testPath, foundPaths)
			} else {
				missingIndicators = append(missingIndicators, indicator)
				if err != nil {
					log.WithFields("cataloger", catalogerName).Tracef("indicator not found: %s (error: %v)", testPath, err)
				} else {
					log.WithFields("cataloger", catalogerName).Tracef("indicator not found: %s (no matching locations)", testPath)
				}
			}
		}
		
		log.WithFields("cataloger", catalogerName).Debugf("build dir %s: found %d/%d indicators - found: %v, missing: %v", 
			buildDir, hasIndicators, len(yoctoIndicators), foundIndicators, missingIndicators)
		
		// If we find at least 2 indicators, consider it a Yocto build dir
		if hasIndicators >= 2 {
			log.WithFields("cataloger", catalogerName).Infof("detected Yocto build directory: %s (found %d/%d indicators: %v)", 
				buildDir, hasIndicators, len(yoctoIndicators), foundIndicators)
			return buildDir
		}
	}

	log.WithFields("cataloger", catalogerName).Debug("no Yocto build directory detected")
	return ""
}

// findLicenseManifest locates the license.manifest file
func (c cataloger) findLicenseManifest(resolver file.Resolver, buildDir string) string {
	// Common locations for license.manifest
	manifestPaths := []string{
		filepath.Join(buildDir, "**/license.manifest"),
	}

	for _, manifestPath := range manifestPaths {
		// Handle glob patterns
		if strings.Contains(manifestPath, "*") {
			// For simplicity, try some common machine names
			machines := []string{"qemux86-64", "qemuarm", "raspberrypi4", "core-image-minimal"}
			for _, machine := range machines {
				expandedPath := strings.Replace(manifestPath, "*", "*-"+machine, 1)
				if locations, err := resolver.FilesByGlob(expandedPath); err == nil && len(locations) > 0 {
					return locations[0].RealPath
				}
			}
			// Also try without machine-specific pattern
			if locations, err := resolver.FilesByGlob(manifestPath); err == nil && len(locations) > 0 {
				return locations[0].RealPath
			}
		} else {
			if locations, err := resolver.FilesByPath(manifestPath); err == nil && len(locations) > 0 {
				return manifestPath
			}
		}
	}

	return ""
}

// parseManifestFile parses the license.manifest file to extract package information
func (c cataloger) parseManifestFile(resolver file.Resolver, manifestPath string) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship

	// Get the location from the resolver first
	locations, err := resolver.FilesByPath(manifestPath)
	if err != nil || len(locations) == 0 {
		return packages, relationships, fmt.Errorf("failed to find manifest file at path %s: %w", manifestPath, err)
	}

	content, err := resolver.FileContentsByLocation(locations[0])
	if err != nil {
		return packages, relationships, fmt.Errorf("failed to read manifest file: %w", err)
	}
	defer content.Close()

	// Read the content
	contentBytes, err := io.ReadAll(content)
	if err != nil {
		return packages, relationships, fmt.Errorf("failed to read content: %w", err)
	}

	lines := strings.Split(string(contentBytes), "\n")
	
	var currentPackage *pkg.Package
	var currentRecipe string
	var currentVersion string
	var currentLicense string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.HasPrefix(line, "RECIPE NAME:") {
			if currentPackage != nil {
				packages = append(packages, *currentPackage)
			}
			currentRecipe = strings.TrimSpace(strings.TrimPrefix(line, "RECIPE NAME:"))
		} else if strings.HasPrefix(line, "PACKAGE VERSION:") || strings.HasPrefix(line, "VERSION:") {
			currentVersion = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(line, "LICENSE:") {
			currentLicense = strings.TrimSpace(strings.TrimPrefix(line, "LICENSE:"))
			
						// Create package when we have recipe name and version
			if currentRecipe != "" && currentVersion != "" {
				currentPackage = &pkg.Package{
					Name:      currentRecipe,
					Version:   currentVersion,
					Type:      pkg.YoctoPkg,
					Language:  pkg.UnknownLanguage,
					Licenses:  pkg.NewLicenseSet(pkg.NewLicense(currentLicense)),
					Locations: file.NewLocationSet(file.NewLocation(manifestPath)),
					PURL:      generateYoctoPURL(currentRecipe, currentVersion),
					Metadata: pkg.YoctoMetadata{
						Name:    currentRecipe,
						Version: currentVersion,
						License: currentLicense,
					},
				}
			}
		} else if line == "" && currentPackage != nil {
			// Empty line indicates end of package entry
			packages = append(packages, *currentPackage)
			currentPackage = nil
			currentRecipe = ""
			currentVersion = ""
			currentLicense = ""
		}
	}

	// Add the last package if exists
	if currentPackage != nil {
		packages = append(packages, *currentPackage)
	}

	return packages, relationships, nil
}

// parseBitbakeCache attempts to parse bitbake cache for additional recipe information
func (c cataloger) parseBitbakeCache(resolver file.Resolver, buildDir string) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship

	log.WithFields("cataloger", catalogerName).Trace("parseBitbakeCache: starting cache parsing", "buildDir", buildDir)

	// Look for bb_cache.dat files anywhere in the build directory
	cachePattern := filepath.Join(buildDir, "**/bb_cache.dat")
	log.WithFields("cataloger", catalogerName).Tracef("searching for cache files with pattern: %s", cachePattern)
	cacheLocations, err := resolver.FilesByGlob(cachePattern)
	if err != nil || len(cacheLocations) == 0 {
		log.WithFields("cataloger", catalogerName).Debug("no bitbake cache files found, skipping cache parsing")
		return packages, relationships, nil
	}

	// Use the first cache file found
	cacheLocation := cacheLocations[0]
	log.WithFields("cataloger", catalogerName).Debugf("found bitbake cache file candidates: AccessPath=%s, RealPath=%s (from %d total)", cacheLocation.AccessPath, cacheLocation.RealPath, len(cacheLocations))
	
	// BitBake cache files often have hash suffixes, use the found file directly
	log.WithFields("cataloger", catalogerName).Debugf("using cache file: %s", cacheLocation.RealPath)

	// Parse the cache using Python helper
	log.WithFields("cataloger", catalogerName).Trace("parsing cache file with Python helper")
	recipes, err := c.parseCacheWithPython(resolver, cacheLocation, buildDir)
	if err != nil {
		log.WithFields("cataloger", catalogerName).Errorf("failed to parse cache file %s: %v", cacheLocation.RealPath, err)
		return packages, relationships, fmt.Errorf("failed to parse cache: %w", err)
	}

	log.WithFields("cataloger", catalogerName).Debugf("successfully parsed cache, found %d recipes", len(recipes))

	// Convert cache recipes to packages
	for _, recipe := range recipes {
		pkg := c.createPackageFromCacheRecipe(recipe, cacheLocation.RealPath)
		packages = append(packages, pkg)
	}

	log.WithFields("cataloger", catalogerName).Debugf("converted %d cache recipes to packages", len(packages))
	return packages, relationships, nil
}

// parseCacheWithPython uses a Python helper script to parse the pickle-format cache file
// The script properly integrates with BitBake environment and dependencies
func (c cataloger) parseCacheWithPython(resolver file.Resolver, cacheLocation file.Location, buildDir string) ([]CacheRecipeInfo, error) {
	log.WithFields("cataloger", catalogerName).Tracef("parseCacheWithPython: starting Python cache parser", "cacheFile", cacheLocation.RealPath)
	log.WithFields("cataloger", catalogerName).Tracef("parseCacheWithPython: starting Python cache parser", "cacheFile", cacheLocation.RealPath)

	// Get cache file contents from resolver
	log.WithFields("cataloger", catalogerName).Tracef("reading cache file contents: %s", cacheLocation.RealPath)
	cacheReader, err := resolver.FileContentsByLocation(cacheLocation)
	if err != nil {
		log.WithFields("cataloger", catalogerName).Errorf("failed to read cache file: %v", err)
		return nil, fmt.Errorf("failed to read cache file: %w", err)
	}
	defer cacheReader.Close()

	// Create temporary cache file for Python script
	log.WithFields("cataloger", catalogerName).Trace("creating temporary cache file")
	tmpCacheFile, err := os.CreateTemp("", "yocto_cache_*.dat")
	if err != nil {
		log.WithFields("cataloger", catalogerName).Errorf("failed to create temporary cache file: %v", err)
		return nil, fmt.Errorf("failed to create temp cache file: %w", err)
	}
	defer os.Remove(tmpCacheFile.Name())
	log.WithFields("cataloger", catalogerName).Tracef("created temporary cache file: %s", tmpCacheFile.Name())

	// Copy cache contents to temporary file
	if _, err := tmpCacheFile.ReadFrom(cacheReader); err != nil {
		tmpCacheFile.Close()
		return nil, fmt.Errorf("failed to copy cache contents: %w", err)
	}
	tmpCacheFile.Close()
	
	cacheFile := tmpCacheFile.Name()
	log.WithFields("cataloger", catalogerName).Tracef("using temporary cache file: %s", cacheFile)

	// Create temporary Python script that uses actual BitBake libraries
	log.WithFields("cataloger", catalogerName).Trace("creating temporary Python cache parser script")
	pythonScript := c.createBitBakeCacheParserScript()
	tmpFile, err := os.CreateTemp("", "yocto_cache_parser_*.py")
	if err != nil {
		log.WithFields("cataloger", catalogerName).Errorf("failed to create temporary script: %v", err)
		return nil, fmt.Errorf("failed to create temp script: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	log.WithFields("cataloger", catalogerName).Tracef("created temporary script: %s", tmpFile.Name())

	if _, err := tmpFile.WriteString(pythonScript); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("failed to write script: %w", err)
	}
	tmpFile.Close()

	// Set up environment for BitBake execution
	log.WithFields("cataloger", catalogerName).Trace("setting up BitBake execution environment")
	cmd := exec.Command("python3", tmpFile.Name(), cacheFile, buildDir)
	
	// Add BitBake to Python path - look for bitbake in workspace or common locations
	log.WithFields("cataloger", catalogerName).Trace("searching for BitBake library paths")
	bitbakePaths := []string{}
	
	// Check for config-specified BitBake paths first
	if c.config.BitBakeLib != "" {
		bitbakePaths = append(bitbakePaths, c.config.BitBakeLib)
	}
	if c.config.BitBakeHome != "" {
		bitbakePaths = append(bitbakePaths, filepath.Join(c.config.BitBakeHome, "lib"))
	}
	
	// Check for user-specified BITBAKE_HOME or BITBAKE_LIB environment variables
	if bitbakeHome := os.Getenv("BITBAKE_HOME"); bitbakeHome != "" {
		bitbakePaths = append(bitbakePaths, filepath.Join(bitbakeHome, "lib"))
	}
	if bitbakeLib := os.Getenv("BITBAKE_LIB"); bitbakeLib != "" {
		bitbakePaths = append(bitbakePaths, bitbakeLib)
	}
	
	// Add common paths
	bitbakePaths = append(bitbakePaths, []string{
		filepath.Join(buildDir, "..", "bitbake", "lib"),        // workspace/bitbake/lib
		filepath.Join(buildDir, "..", "..", "bitbake", "lib"),  // ../workspace/bitbake/lib
		filepath.Join(buildDir, "bitbake", "lib"),              // build/bitbake/lib
		"/usr/lib/python3/dist-packages",                       // system installation
		"/usr/local/lib/python3/dist-packages",                // local installation
		"/opt/yocto/bitbake/lib",                               // yocto installation
	}...)
	
	var pythonPath string
	var foundPaths []string
	for _, path := range bitbakePaths {
		if _, err := os.Stat(filepath.Join(path, "bb")); err == nil {
			foundPaths = append(foundPaths, path)
			if pythonPath == "" {
				pythonPath = path
			} else {
				pythonPath = pythonPath + ":" + path
			}
		}
	}
	
	if pythonPath != "" {
		log.WithFields("cataloger", catalogerName).Debugf("found BitBake libraries at: %v", foundPaths)
		log.WithFields("cataloger", catalogerName).Tracef("setting PYTHONPATH: %s", pythonPath)
		env := os.Environ()
		env = append(env, "PYTHONPATH="+pythonPath)
		// Add additional BitBake environment variables that might be needed
		env = append(env, "BB_ENV_PASSTHROUGH_ADDITIONS="+os.Getenv("BB_ENV_PASSTHROUGH_ADDITIONS"))
		if bbSkipNetTests := os.Getenv("BB_SKIP_NETTESTS"); bbSkipNetTests != "" {
			env = append(env, "BB_SKIP_NETTESTS="+bbSkipNetTests)
		}
		cmd.Env = env
	} else {
		log.WithFields("cataloger", catalogerName).Warn("no BitBake libraries found in any search paths, cache parsing may fail")
	}

	log.WithFields("cataloger", catalogerName).Trace("executing Python cache parser with python3")
	output, err := cmd.Output()
	if err != nil {
		log.WithFields("cataloger", catalogerName).Tracef("python3 execution failed: %v, trying python", err)
		// Try python if python3 is not available
		cmd = exec.Command("python", tmpFile.Name(), cacheFile, buildDir)
		if pythonPath != "" {
			env := os.Environ()
			env = append(env, "PYTHONPATH="+pythonPath)
			// Add additional BitBake environment variables that might be needed
			env = append(env, "BB_ENV_PASSTHROUGH_ADDITIONS="+os.Getenv("BB_ENV_PASSTHROUGH_ADDITIONS"))
			if bbSkipNetTests := os.Getenv("BB_SKIP_NETTESTS"); bbSkipNetTests != "" {
				env = append(env, "BB_SKIP_NETTESTS="+bbSkipNetTests)
			}
			cmd.Env = env
		}
		log.WithFields("cataloger", catalogerName).Trace("executing Python cache parser with python")
		output, err = cmd.Output()
		if err != nil {
			log.WithFields("cataloger", catalogerName).Errorf("both python3 and python execution failed: %v", err)
			return nil, fmt.Errorf("failed to execute cache parser (tried both python3 and python): %w", err)
		}
	}

	// Parse JSON output
	log.WithFields("cataloger", catalogerName).Tracef("parsing JSON output from Python cache parser (%d bytes)", len(output))
	var recipes []CacheRecipeInfo
	if err := json.Unmarshal(output, &recipes); err != nil {
		log.WithFields("cataloger", catalogerName).Errorf("failed to parse JSON output: %v", err)
		log.WithFields("cataloger", catalogerName).Tracef("JSON output was: %s", string(output))
		return nil, fmt.Errorf("failed to parse cache output: %w", err)
	}

	log.WithFields("cataloger", catalogerName).Debugf("successfully parsed cache, extracted %d recipe(s)", len(recipes))
	return recipes, nil
}

// createBitBakeCacheParserScript generates a Python script that uses actual BitBake libraries
func (c cataloger) createBitBakeCacheParserScript() string {
	return `#!/usr/bin/env python3
import sys
import os
import json
import re

def main():
    if len(sys.argv) != 3:
        print("Usage: script.py <cache_file> <build_dir>", file=sys.stderr)
        sys.exit(1)
    
    cache_file = sys.argv[1]
    build_dir = sys.argv[2]
    
    try:
        # Try to import and use actual BitBake libraries
        import bb.cache
        import bb.cooker
        import bb.data
        import bb.parse
        import bb.utils
        import pickle
        
        recipes = parse_cache_file_with_bitbake(cache_file, build_dir)
        
    except ImportError as e:
        print(f"BitBake libraries not available: {e}, falling back to basic parsing", file=sys.stderr)
        # Fallback to basic parsing without full BitBake dependencies
        recipes = parse_cache_file_basic(cache_file, build_dir)
        
    print(json.dumps(recipes, indent=2))

def parse_cache_file_with_bitbake(cache_file, build_dir):
    """Parse using actual BitBake libraries when available"""
    import bb.cache
    import pickle
    
    recipes = []
    
    try:
        with open(cache_file, 'rb') as f:
            unpickler = pickle.Unpickler(f)
            
            # Read cache version and bitbake version
            try:
                cache_ver = unpickler.load()
                bitbake_ver = unpickler.load()
                print(f"Cache version: {cache_ver}, BitBake version: {bitbake_ver}", file=sys.stderr)
            except Exception as e:
                print(f"Error reading version: {e}", file=sys.stderr)
                return recipes
            
            # Read recipe data
            entry_count = 0
            success_count = 0
            while entry_count < 1000:  # Limit to prevent infinite loops
                try:
                    key = unpickler.load()
                    value = unpickler.load()
                    entry_count += 1
                    
                    if not isinstance(key, str):
                        continue
                    
                    # Extract recipe information using BitBake objects
                    if hasattr(value, 'pn') and hasattr(value, 'pv'):
                        recipe_info = {
                            'filename': key,
                            'pn': getattr(value, 'pn', ''),
                            'pv': getattr(value, 'pv', ''),
                            'pe': getattr(value, 'pe', ''),
                            'pr': getattr(value, 'pr', ''),
                            'license': getattr(value, 'license', '') if hasattr(value, 'license') else '',
                            'provides': list(getattr(value, 'provides', [])),
                            'depends': list(getattr(value, 'depends', [])),
                            'rdepends': dict(getattr(value, 'rdepends_pkg', {})),
                            'packages': list(getattr(value, 'packages', [])),
                            'layer': extract_layer_from_path(key, build_dir),
                            'recipe': os.path.basename(key) if key else ''
                        }
                        
                        # Only add if we have valid package name and version
                        if recipe_info['pn'] and recipe_info['pv']:
                            recipes.append(recipe_info)
                            success_count += 1
                            
                except EOFError:
                    print(f"Reached end of file after {entry_count} entries", file=sys.stderr)
                    break
                except Exception as e:
                    print(f"Error processing entry {entry_count}: {e}", file=sys.stderr)
                    continue
                    
            print(f"Successfully processed {success_count} out of {entry_count} entries", file=sys.stderr)
                    
    except Exception as e:
        print(f"Error opening cache file: {e}", file=sys.stderr)
    
    return recipes

def parse_cache_file_basic(cache_file, build_dir):
    """Basic parsing without full BitBake dependencies"""
    import pickle
    
    recipes = []
    
    try:
        with open(cache_file, 'rb') as f:
            unpickler = pickle.Unpickler(f)
            
            # Read cache version and bitbake version
            try:
                cache_ver = unpickler.load()
                bitbake_ver = unpickler.load()
                print(f"Cache version: {cache_ver}, BitBake version: {bitbake_ver}", file=sys.stderr)
            except Exception as e:
                print(f"Error reading version: {e}", file=sys.stderr)
                return recipes
            
            # Read recipe data with basic attribute access
            entry_count = 0
            success_count = 0
            while entry_count < 1000:  # Limit to prevent infinite loops
                try:
                    key = unpickler.load()
                    value = unpickler.load()
                    entry_count += 1
                    
                    if not isinstance(key, str):
                        continue
                    
                    # Extract recipe information with safe attribute access
                    try:
                        recipe_info = {
                            'filename': key,
                            'pn': safe_getattr(value, 'pn', ''),
                            'pv': safe_getattr(value, 'pv', ''),
                            'pe': safe_getattr(value, 'pe', ''),
                            'pr': safe_getattr(value, 'pr', ''),
                            'license': safe_getattr(value, 'license', ''),
                            'provides': list(safe_getattr(value, 'provides', [])),
                            'depends': list(safe_getattr(value, 'depends', [])),
                            'rdepends': dict(safe_getattr(value, 'rdepends_pkg', {})) if hasattr(value, 'rdepends_pkg') else {},
                            'packages': list(safe_getattr(value, 'packages', [])),
                            'layer': extract_layer_from_path(key, build_dir),
                            'recipe': os.path.basename(key) if key else ''
                        }
                        
                        # Only add if we have valid package name and version
                        if recipe_info['pn'] and recipe_info['pv']:
                            recipes.append(recipe_info)
                            success_count += 1
                            
                    except Exception as e:
                        print(f"Error processing entry {entry_count}: {e}", file=sys.stderr)
                        continue
                        
                except EOFError:
                    print(f"Reached end of file after {entry_count} entries", file=sys.stderr)
                    break
                except Exception as e:
                    print(f"Error reading entry {entry_count}: {e}", file=sys.stderr)
                    continue
                    
            print(f"Successfully processed {success_count} out of {entry_count} entries", file=sys.stderr)
                    
    except Exception as e:
        print(f"Error opening cache file: {e}", file=sys.stderr)
    
    return recipes

def safe_getattr(obj, attr, default):
    """Safely get attribute with fallback"""
    try:
        return getattr(obj, attr, default)
    except:
        return default

def extract_layer_from_path(file_path, build_dir):
    """Extract layer name from recipe file path"""
    if not file_path:
        return ""
    
    # Remove build directory prefix if present
    if file_path.startswith(build_dir):
        file_path = file_path[len(build_dir):].lstrip('/')
    
    # Look for meta-* patterns or common layer names
    parts = file_path.split('/')
    for part in parts:
        if part.startswith('meta-') or part in ['meta', 'oe-core', 'openembedded-core']:
            return part
    
    # If no meta- layer found, use first directory
    if parts:
        return parts[0]
    
    return ""

if __name__ == '__main__':
    main()
`
}



// createPackageFromCacheRecipe converts a CacheRecipeInfo to a pkg.Package
func (c cataloger) createPackageFromCacheRecipe(recipe CacheRecipeInfo, cacheFile string) pkg.Package {
	// Build version string
	version := recipe.Version
	if recipe.PackageEpoch != "" && recipe.PackageEpoch != "0" {
		version = recipe.PackageEpoch + ":" + version
	}
	if recipe.Release != "" {
		version = version + "-" + recipe.Release
	}

	// Extract dependencies
	var dependencies []string
	dependencies = append(dependencies, recipe.Depends...)
	for _, rdeps := range recipe.RDepends {
		dependencies = append(dependencies, rdeps...)
	}

	// Create metadata
	metadata := pkg.YoctoMetadata{
		Name:         recipe.PackageName,
		Version:      recipe.Version,
		License:      recipe.License,
		Layer:        recipe.Layer,
		Recipe:       recipe.Recipe,
		Epoch:        recipe.PackageEpoch,
		Release:      recipe.Release,
		Dependencies: dependencies,
	}

	// Create package
	return pkg.Package{
		Name:      recipe.PackageName,
		Version:   version,
		Type:      pkg.YoctoPkg,
		Language:  pkg.UnknownLanguage,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense(recipe.License)),
		Locations: file.NewLocationSet(file.NewLocation(cacheFile)),
		PURL:      generateYoctoPURL(recipe.PackageName, version),
		Metadata:  metadata,
	}
}

// generateYoctoPURL generates a Package URL for Yocto/OpenEmbedded packages
func generateYoctoPURL(name, version string) string {
	// Generate PURL in the format: pkg:openembedded/meta/name@version
	return fmt.Sprintf("pkg:openembedded/meta/%s@%s", name, version)
}
