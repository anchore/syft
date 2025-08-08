/*
Package yocto provides a concrete Cataloger implementation for Yocto/OpenEmbedded build systems.
*/
package yocto

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const catalogerName = "yocto-cataloger"

type Config struct {
	BuildDir string `yaml:"build-dir" json:"build-dir" mapstructure:"build-dir"`
}

func DefaultConfig() Config {
	return Config{
		BuildDir: "build",
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
func (c cataloger) detectYoctoBuildDir(resolver file.Resolver) string {
	// Look for typical Yocto build directory structure
	yoctoIndicators := []string{
		"conf/bblayers.conf",
		"conf/local.conf",
		"tmp/cache",
		"tmp/deploy",
	}

	// Check if build directory is specified in config
	if c.config.BuildDir != "" {
		for _, indicator := range yoctoIndicators {
			testPath := filepath.Join(c.config.BuildDir, indicator)
			if _, err := resolver.FilesByPath(testPath); err == nil {
				return c.config.BuildDir
			}
		}
	}

	// Look for build directory in common locations
	commonBuildDirs := []string{
		"build",
		"poky/build", 
		"yocto/build",
		".",
	}

	for _, buildDir := range commonBuildDirs {
		hasIndicators := 0
		for _, indicator := range yoctoIndicators {
			testPath := filepath.Join(buildDir, indicator)
			if _, err := resolver.FilesByPath(testPath); err == nil {
				hasIndicators++
			}
		}
		// If we find at least 2 indicators, consider it a Yocto build dir
		if hasIndicators >= 2 {
			return buildDir
		}
	}

	return ""
}

// findLicenseManifest locates the license.manifest file
func (c cataloger) findLicenseManifest(resolver file.Resolver, buildDir string) string {
	// Common locations for license.manifest
	manifestPaths := []string{
		"license.manifest", // Check root first
		filepath.Join(buildDir, "license.manifest"),
		filepath.Join(buildDir, "tmp/deploy/licenses/*/license.manifest"),
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

	// Look for bb_cache.dat files
	cachePattern := filepath.Join(buildDir, "tmp/cache/*/*/*/*/bb_cache.dat")
	cacheLocations, err := resolver.FilesByGlob(cachePattern)
	if err != nil || len(cacheLocations) == 0 {
		// Try alternative pattern
		cachePattern = filepath.Join(buildDir, "tmp/cache/bb_cache.dat")
		cacheLocations, err = resolver.FilesByGlob(cachePattern)
		if err != nil || len(cacheLocations) == 0 {
			return packages, relationships, nil
		}
	}

	// For now, we'll skip the complex cache parsing since it requires
	// Python pickle parsing which is complex in Go. This could be
	// extended in the future with a Python helper or native implementation.
	
	return packages, relationships, nil
}

// generateYoctoPURL generates a Package URL for Yocto/OpenEmbedded packages
func generateYoctoPURL(name, version string) string {
	// Generate PURL in the format: pkg:openembedded/meta/name@version
	return fmt.Sprintf("pkg:openembedded/meta/%s@%s", name, version)
}
