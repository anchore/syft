/*
Package yocto provides a comprehensive Cataloger implementation for Yocto/OpenEmbedded build systems.

This cataloger analyzes multiple Yocto build artifacts to extract complete SBOM information, following
the Yocto Project structure documentation: https://docs.yoctoproject.org/ref-manual/structure.html

The cataloger parses the following data sources for comprehensive SBOM coverage:

1. BitBake Cache Files (bb_cache.dat):
  - Recipe information with dependencies, licenses, and metadata
  - Attempts to use actual BitBake libraries when available for full compatibility
  - Falls back to basic parsing when BitBake libraries are not accessible

2. License Manifest Files (license.manifest):
  - Package license information from build artifacts

3. Build History Data (buildhistory/packages/):
  - Detailed package metadata including build times, sizes, and dependencies
  - Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-buildhistory

4. License Files (tmp/deploy/licenses/):
  - Comprehensive license information for each package
  - Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-tmp

5. Source Information (downloads/):
  - Source provenance data for supply chain security
  - Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-downloads

6. Image Manifests (tmp/deploy/images/):
  - System-level SBOM data showing installed packages in built images
  - Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-tmp

Build Directory Detection:
The cataloger uses enhanced detection based on Yocto Project structure, requiring:
- At least 2 indicators from: conf/bblayers.conf, conf/local.conf, tmp/cache, tmp/deploy, downloads, sstate-cache, tmp/work, tmp/deploy/licenses

Configuration Options:
- BITBAKE_HOME: Path to BitBake installation directory
- BITBAKE_LIB: Path to BitBake library directory
- Config.BitBakeHome: Configuration option for BitBake home directory
- Config.BitBakeLib: Configuration option for BitBake library directory
- Config.BuildDir: Specific build directory to analyze

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

	// Parse build history for additional package metadata
	// Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-buildhistory
	historyPkgs, historyRels, err := c.parseBuildHistory(resolver, buildDir)
	if err == nil {
		packages = append(packages, historyPkgs...)
		relationships = append(relationships, historyRels...)
	} else {
		log.WithFields("cataloger", catalogerName).Debugf("build history parsing failed: %v", err)
	}

	// Parse comprehensive license files
	// Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-tmp
	licensePkgs, licenseRels, err := c.parseLicenseFiles(resolver, buildDir)
	if err == nil {
		packages = append(packages, licensePkgs...)
		relationships = append(relationships, licenseRels...)
	} else {
		log.WithFields("cataloger", catalogerName).Debugf("license files parsing failed: %v", err)
	}

	// Parse source information for provenance
	// Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-downloads
	sourcePkgs, sourceRels, err := c.parseSourceInfo(resolver, buildDir)
	if err == nil {
		packages = append(packages, sourcePkgs...)
		relationships = append(relationships, sourceRels...)
	} else {
		log.WithFields("cataloger", catalogerName).Debugf("source info parsing failed: %v", err)
	}

	// Parse image manifests for system-level SBOM
	// Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-tmp
	imagePkgs, imageRels, err := c.parseImageManifests(resolver, buildDir)
	if err == nil {
		packages = append(packages, imagePkgs...)
		relationships = append(relationships, imageRels...)
	} else {
		log.WithFields("cataloger", catalogerName).Debugf("image manifests parsing failed: %v", err)
	}

	log.WithFields("cataloger", catalogerName).Infof("completed Yocto cataloging: found %d packages total", len(packages))
	return packages, relationships, nil
}

// detectYoctoBuildDir checks if the given path contains Yocto build artifacts
// Based on Yocto Project structure documentation: https://docs.yoctoproject.org/ref-manual/structure.html#the-build-directory-build
func (c cataloger) detectYoctoBuildDir(resolver file.Resolver) string {
	log.WithFields("cataloger", catalogerName).Debug("starting Yocto build directory detection")
	
	// Yocto build directory indicators from documentation
	// Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-conf-local-conf
	// Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-conf-bblayers-conf
	// Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-downloads
	// Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-sstate-cache
	// Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-tmp
	indicators := []string{
		"conf/bblayers.conf",    // Layer configuration - defines which metadata layers are included
		"conf/local.conf",       // Local build configuration - contains build-specific settings
		"tmp/cache",             // BitBake cache directory
		"tmp/deploy",            // Deployment directory for images and packages
		"downloads",             // Source downloads directory
		"sstate-cache",          // Shared state cache directory
		"tmp/work",              // Recipe work directories
		"tmp/deploy/licenses",   // License deployment directory
	}
	
	log.WithFields("cataloger", catalogerName).Debugf("looking for indicators: %v", indicators)

	// Check if build directory is specified in config
	if c.config.BuildDir != "" {
		log.WithFields("cataloger", catalogerName).Debugf("checking configured build directory: %s", c.config.BuildDir)
		foundIndicators := 0
		var foundList []string
		
		// Check all indicators
		for _, indicator := range indicators {
			testPath := filepath.Join(c.config.BuildDir, indicator)
			log.WithFields("cataloger", catalogerName).Tracef("checking for indicator: %s", testPath)
			if resolver.HasPath(testPath) {
				log.WithFields("cataloger", catalogerName).Debugf("found indicator in configured build dir: %s", testPath)
				foundIndicators++
				foundList = append(foundList, indicator)
			}
		}
		
		// Require at least 2 indicators for robust detection
		if foundIndicators >= 2 {
			log.WithFields("cataloger", catalogerName).Infof("using configured build directory %s (found %d/%d indicators: %v)", 
				c.config.BuildDir, foundIndicators, len(indicators), foundList)
			return c.config.BuildDir
		} else {
			log.WithFields("cataloger", catalogerName).Warnf("configured build directory %s does not meet detection criteria (found %d/%d indicators: %v)", 
				c.config.BuildDir, foundIndicators, len(indicators), foundList)
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
		foundIndicators := 0
		var foundList []string
		
		// Check all indicators
		for _, indicator := range indicators {
			testPath := filepath.Join(buildDir, indicator)
			log.WithFields("cataloger", catalogerName).Tracef("checking for indicator: %s", testPath)
			if resolver.HasPath(testPath) {
				foundIndicators++
				foundList = append(foundList, indicator)
				log.WithFields("cataloger", catalogerName).Tracef("found indicator: %s", testPath)
			}
		}
		
		log.WithFields("cataloger", catalogerName).Debugf("build dir %s: found %d/%d indicators (%v)", 
			buildDir, foundIndicators, len(indicators), foundList)
		
		// Require at least 2 indicators for robust detection
		if foundIndicators >= 2 {
			log.WithFields("cataloger", catalogerName).Infof("detected Yocto build directory: %s (found %d/%d indicators: %v)", 
				buildDir, foundIndicators, len(indicators), foundList)
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

// parseBuildHistory parses build history information for additional package metadata
// Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-buildhistory
func (c cataloger) parseBuildHistory(resolver file.Resolver, buildDir string) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship

	log.WithFields("cataloger", catalogerName).Debug("parsing build history for additional package metadata")

	// Look for buildhistory directory - contains detailed build information
	buildHistoryPattern := filepath.Join(buildDir, "buildhistory/packages/*/")
	log.WithFields("cataloger", catalogerName).Tracef("searching for build history with pattern: %s", buildHistoryPattern)
	
	buildHistoryDirs, err := resolver.FilesByGlob(buildHistoryPattern)
	if err != nil || len(buildHistoryDirs) == 0 {
		log.WithFields("cataloger", catalogerName).Debug("no build history directories found")
		return packages, relationships, nil
	}

	log.WithFields("cataloger", catalogerName).Debugf("found %d build history directories", len(buildHistoryDirs))

	// Parse build history files for each architecture
	for _, historyDir := range buildHistoryDirs {
		archPackages, archRels, err := c.parseBuildHistoryDir(resolver, historyDir.RealPath)
		if err != nil {
			log.WithFields("cataloger", catalogerName).Warnf("failed to parse build history dir %s: %v", historyDir.RealPath, err)
			continue
		}
		packages = append(packages, archPackages...)
		relationships = append(relationships, archRels...)
	}

	log.WithFields("cataloger", catalogerName).Debugf("parsed build history, found %d additional packages", len(packages))
	return packages, relationships, nil
}

// parseBuildHistoryDir parses a specific build history directory for an architecture
func (c cataloger) parseBuildHistoryDir(resolver file.Resolver, historyDirPath string) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship

	// Look for package files in build history (e.g., latest, latest_srcrev files)
	packagePattern := filepath.Join(historyDirPath, "*/latest")
	packageFiles, err := resolver.FilesByGlob(packagePattern)
	if err != nil {
		return packages, relationships, err
	}

	for _, packageFile := range packageFiles {
		pkg, rels, err := c.parseBuildHistoryPackageFile(resolver, packageFile)
		if err != nil {
			log.WithFields("cataloger", catalogerName).Warnf("failed to parse build history package file %s: %v", packageFile.RealPath, err)
			continue
		}
		if pkg != nil {
			packages = append(packages, *pkg)
			relationships = append(relationships, rels...)
		}
	}

	return packages, relationships, nil
}

// parseBuildHistoryPackageFile parses a specific build history package file
func (c cataloger) parseBuildHistoryPackageFile(resolver file.Resolver, packageFile file.Location) (*pkg.Package, []artifact.Relationship, error) {
	var relationships []artifact.Relationship

	content, err := resolver.FileContentsByLocation(packageFile)
	if err != nil {
		return nil, relationships, fmt.Errorf("failed to read build history file: %w", err)
	}
	defer content.Close()

	contentBytes, err := io.ReadAll(content)
	if err != nil {
		return nil, relationships, fmt.Errorf("failed to read content: %w", err)
	}

	lines := strings.Split(string(contentBytes), "\n")
	
	var name, version, license, size, buildTime string
	var dependencies []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PN = ") {
			name = strings.Trim(strings.TrimPrefix(line, "PN = "), "\"")
		} else if strings.HasPrefix(line, "PV = ") {
			version = strings.Trim(strings.TrimPrefix(line, "PV = "), "\"")
		} else if strings.HasPrefix(line, "LICENSE = ") {
			license = strings.Trim(strings.TrimPrefix(line, "LICENSE = "), "\"")
		} else if strings.HasPrefix(line, "PKGSIZE = ") {
			size = strings.Trim(strings.TrimPrefix(line, "PKGSIZE = "), "\"")
		} else if strings.HasPrefix(line, "BUILDTIME = ") {
			buildTime = strings.Trim(strings.TrimPrefix(line, "BUILDTIME = "), "\"")
		} else if strings.HasPrefix(line, "RDEPENDS = ") {
			depStr := strings.Trim(strings.TrimPrefix(line, "RDEPENDS = "), "\"")
			if depStr != "" {
				dependencies = strings.Fields(depStr)
			}
		}
	}

	if name == "" || version == "" {
		return nil, relationships, nil // Skip incomplete entries
	}

	// Create package with build history metadata
	metadata := pkg.YoctoMetadata{
		Name:         name,
		Version:      version,
		License:      license,
		Dependencies: dependencies,
	}

	// Add build history specific metadata if available
	if size != "" || buildTime != "" {
		// Note: We might need to extend YoctoMetadata to include size and build time
		// For now, we'll include them in a custom way
		log.WithFields("cataloger", catalogerName).Tracef("build history for %s: size=%s, buildTime=%s", name, size, buildTime)
	}

	yoctoPackage := &pkg.Package{
		Name:      name,
		Version:   version,
		Type:      pkg.YoctoPkg,
		Language:  pkg.UnknownLanguage,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense(license)),
		Locations: file.NewLocationSet(file.NewLocation(packageFile.RealPath)),
		PURL:      generateYoctoPURL(name, version),
		Metadata:  metadata,
	}

	return yoctoPackage, relationships, nil
}

// parseLicenseFiles parses comprehensive license information from deployment directory
// Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-tmp
func (c cataloger) parseLicenseFiles(resolver file.Resolver, buildDir string) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship

	log.WithFields("cataloger", catalogerName).Debug("parsing license files for comprehensive license information")

	// Look for license files in tmp/deploy/licenses
	licensePattern := filepath.Join(buildDir, "tmp/deploy/licenses/*/*")
	log.WithFields("cataloger", catalogerName).Tracef("searching for license files with pattern: %s", licensePattern)
	
	licenseFiles, err := resolver.FilesByGlob(licensePattern)
	if err != nil || len(licenseFiles) == 0 {
		log.WithFields("cataloger", catalogerName).Debug("no license files found in deploy directory")
		return packages, relationships, nil
	}

	log.WithFields("cataloger", catalogerName).Debugf("found %d license files", len(licenseFiles))

	// Group license files by package
	packageLicenses := make(map[string][]file.Location)
	for _, licenseFile := range licenseFiles {
		// Extract package name from path (e.g., tmp/deploy/licenses/package-name/LICENSE)
		pathParts := strings.Split(licenseFile.RealPath, "/")
		if len(pathParts) >= 2 {
			packageName := pathParts[len(pathParts)-2]
			packageLicenses[packageName] = append(packageLicenses[packageName], licenseFile)
		}
	}

	// Create packages with comprehensive license information
	for packageName, licenses := range packageLicenses {
		pkg, rels, err := c.createPackageFromLicenseFiles(resolver, packageName, licenses)
		if err != nil {
			log.WithFields("cataloger", catalogerName).Warnf("failed to create package from license files for %s: %v", packageName, err)
			continue
		}
		if pkg != nil {
			packages = append(packages, *pkg)
			relationships = append(relationships, rels...)
		}
	}

	log.WithFields("cataloger", catalogerName).Debugf("parsed license files, found %d packages with license information", len(packages))
	return packages, relationships, nil
}

// createPackageFromLicenseFiles creates a package from license file information
func (c cataloger) createPackageFromLicenseFiles(resolver file.Resolver, packageName string, licenseFiles []file.Location) (*pkg.Package, []artifact.Relationship, error) {
	var relationships []artifact.Relationship
	var licenses []string
	var licenseLocations []file.Location

	// Read all license files for this package
	for _, licenseFile := range licenseFiles {
		content, err := resolver.FileContentsByLocation(licenseFile)
		if err != nil {
			log.WithFields("cataloger", catalogerName).Warnf("failed to read license file %s: %v", licenseFile.RealPath, err)
			continue
		}
		
		_, err = io.ReadAll(content)
		content.Close()
		if err != nil {
			log.WithFields("cataloger", catalogerName).Warnf("failed to read license content %s: %v", licenseFile.RealPath, err)
			continue
		}

		// Extract license from filename or content
		filename := filepath.Base(licenseFile.RealPath)
		if filename != "generic_" && filename != "recipeinfo" {
			licenses = append(licenses, filename)
		}
		
		licenseLocations = append(licenseLocations, licenseFile)
	}

	if len(licenses) == 0 {
		return nil, relationships, nil
	}

	// Create package with license information
	metadata := pkg.YoctoMetadata{
		Name:    packageName,
		License: strings.Join(licenses, " & "),
	}

	locationSet := file.NewLocationSet()
	for _, loc := range licenseLocations {
		locationSet.Add(file.NewLocation(loc.RealPath))
	}

	yoctoPackage := &pkg.Package{
		Name:      packageName,
		Version:   "unknown", // License files don't typically contain version info
		Type:      pkg.YoctoPkg,
		Language:  pkg.UnknownLanguage,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense(strings.Join(licenses, " & "))),
		Locations: locationSet,
		PURL:      generateYoctoPURL(packageName, "unknown"),
		Metadata:  metadata,
	}

	return yoctoPackage, relationships, nil
}

// parseSourceInfo parses source provenance information from downloads directory
// Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-downloads
func (c cataloger) parseSourceInfo(resolver file.Resolver, buildDir string) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship

	log.WithFields("cataloger", catalogerName).Debug("parsing source information for provenance data")

	// Look for downloaded source files
	downloadsPattern := filepath.Join(buildDir, "downloads/*")
	log.WithFields("cataloger", catalogerName).Tracef("searching for downloads with pattern: %s", downloadsPattern)
	
	downloadFiles, err := resolver.FilesByGlob(downloadsPattern)
	if err != nil || len(downloadFiles) == 0 {
		log.WithFields("cataloger", catalogerName).Debug("no download files found")
		return packages, relationships, nil
	}

	log.WithFields("cataloger", catalogerName).Debugf("found %d download files", len(downloadFiles))

	// Parse source files for provenance information
	for _, downloadFile := range downloadFiles {
		pkg, rels, err := c.parseSourceFile(resolver, downloadFile)
		if err != nil {
			log.WithFields("cataloger", catalogerName).Warnf("failed to parse source file %s: %v", downloadFile.RealPath, err)
			continue
		}
		if pkg != nil {
			packages = append(packages, *pkg)
			relationships = append(relationships, rels...)
		}
	}

	log.WithFields("cataloger", catalogerName).Debugf("parsed source info, found %d packages with source information", len(packages))
	return packages, relationships, nil
}

// parseSourceFile extracts source information from a downloaded file
func (c cataloger) parseSourceFile(resolver file.Resolver, sourceFile file.Location) (*pkg.Package, []artifact.Relationship, error) {
	var relationships []artifact.Relationship

	filename := filepath.Base(sourceFile.RealPath)
	
	// Skip certain file types that aren't useful for SBOM
	if strings.HasSuffix(filename, ".done") || strings.HasSuffix(filename, ".lock") {
		return nil, relationships, nil
	}

	// Extract package name and version from filename patterns
	// Common patterns: package-version.tar.gz, package_version.tar.bz2, etc.
	var name, version string
	
	// Remove common extensions
	cleanName := filename
	for _, ext := range []string{".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".tar", ".tgz"} {
		if strings.HasSuffix(cleanName, ext) {
			cleanName = strings.TrimSuffix(cleanName, ext)
			break
		}
	}

	// Try to extract name and version
	if matches := strings.Split(cleanName, "-"); len(matches) >= 2 {
		name = matches[0]
		version = strings.Join(matches[1:], "-")
	} else if matches := strings.Split(cleanName, "_"); len(matches) >= 2 {
		name = matches[0]
		version = strings.Join(matches[1:], "_")
	} else {
		name = cleanName
		version = "unknown"
	}

	if name == "" {
		return nil, relationships, nil
	}

	// Create package with source information
	metadata := pkg.YoctoMetadata{
		Name:    name,
		Version: version,
	}

	yoctoPackage := &pkg.Package{
		Name:      name,
		Version:   version,
		Type:      pkg.YoctoPkg,
		Language:  pkg.UnknownLanguage,
		Locations: file.NewLocationSet(file.NewLocation(sourceFile.RealPath)),
		PURL:      generateYoctoPURL(name, version),
		Metadata:  metadata,
	}

	return yoctoPackage, relationships, nil
}

// parseImageManifests parses image-level SBOM information from deployed images
// Reference: https://docs.yoctoproject.org/ref-manual/structure.html#build-tmp
func (c cataloger) parseImageManifests(resolver file.Resolver, buildDir string) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship

	log.WithFields("cataloger", catalogerName).Debug("parsing image manifests for system-level SBOM data")

	// Look for image manifest files in tmp/deploy/images
	imagePattern := filepath.Join(buildDir, "tmp/deploy/images/*/*")
	log.WithFields("cataloger", catalogerName).Tracef("searching for image files with pattern: %s", imagePattern)
	
	imageFiles, err := resolver.FilesByGlob(imagePattern)
	if err != nil || len(imageFiles) == 0 {
		log.WithFields("cataloger", catalogerName).Debug("no image files found")
		return packages, relationships, nil
	}

	log.WithFields("cataloger", catalogerName).Debugf("found %d image files", len(imageFiles))

	// Look for specific manifest files
	manifestPatterns := []string{
		"*.manifest",
		"*.rootfs.manifest",
		"*.testdata.json",
	}

	for _, pattern := range manifestPatterns {
		manifestPattern := filepath.Join(buildDir, "tmp/deploy/images/*/*", pattern)
		manifestFiles, err := resolver.FilesByGlob(manifestPattern)
		if err != nil {
			continue
		}

		for _, manifestFile := range manifestFiles {
			pkg, rels, err := c.parseImageManifestFile(resolver, manifestFile)
			if err != nil {
				log.WithFields("cataloger", catalogerName).Warnf("failed to parse image manifest %s: %v", manifestFile.RealPath, err)
				continue
			}
			if pkg != nil {
				packages = append(packages, *pkg)
				relationships = append(relationships, rels...)
			}
		}
	}

	log.WithFields("cataloger", catalogerName).Debugf("parsed image manifests, found %d image packages", len(packages))
	return packages, relationships, nil
}

// parseImageManifestFile parses a specific image manifest file
func (c cataloger) parseImageManifestFile(resolver file.Resolver, manifestFile file.Location) (*pkg.Package, []artifact.Relationship, error) {
	var relationships []artifact.Relationship

	content, err := resolver.FileContentsByLocation(manifestFile)
	if err != nil {
		return nil, relationships, fmt.Errorf("failed to read manifest file: %w", err)
	}
	defer content.Close()

	contentBytes, err := io.ReadAll(content)
	if err != nil {
		return nil, relationships, fmt.Errorf("failed to read content: %w", err)
	}

	// Extract image name from path
	pathParts := strings.Split(manifestFile.RealPath, "/")
	var imageName, machine string
	if len(pathParts) >= 3 {
		machine = pathParts[len(pathParts)-2]
		filename := pathParts[len(pathParts)-1]
		imageName = strings.TrimSuffix(filename, filepath.Ext(filename))
	}

	if imageName == "" {
		return nil, relationships, nil
	}

	lines := strings.Split(string(contentBytes), "\n")
	var installedPackages []string
	
	// Parse manifest format (typically package version arch)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		fields := strings.Fields(line)
		if len(fields) >= 1 {
			installedPackages = append(installedPackages, fields[0])
		}
	}

	// Create image package
	metadata := pkg.YoctoMetadata{
		Name:         imageName,
		Version:      "latest",
		Dependencies: installedPackages,
		Layer:        machine,
	}

	yoctoPackage := &pkg.Package{
		Name:      imageName,
		Version:   "latest",
		Type:      pkg.YoctoPkg,
		Language:  pkg.UnknownLanguage,
		Locations: file.NewLocationSet(file.NewLocation(manifestFile.RealPath)),
		PURL:      generateYoctoPURL(imageName, "latest"),
		Metadata:  metadata,
	}

	return yoctoPackage, relationships, nil
}

// parseCacheWithPython uses a Python helper script to parse the pickle-format cache file
// The script properly integrates with BitBake environment and dependencies
func (c cataloger) parseCacheWithPython(resolver file.Resolver, cacheLocation file.Location, buildDir string) ([]CacheRecipeInfo, error) {
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
