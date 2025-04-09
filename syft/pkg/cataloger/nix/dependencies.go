package nix

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

// findDependencies attempts to find relationships between Nix packages
// without using external commands
func findDependencies(pkgs []pkg.Package) ([]artifact.Relationship, error) {
	var relationships []artifact.Relationship
	packageByPath := make(map[string]*pkg.Package)
	packageByStorePath := make(map[string]*pkg.Package)

	// Index packages by store path and path for quick lookups
	for i := range pkgs {
		p := &pkgs[i]
		metadata, ok := p.Metadata.(pkg.NixStoreEntry)
		if !ok {
			continue
		}

		packageByStorePath[metadata.Path] = p

		// Also index by the package files
		for _, filePath := range metadata.Files {
			packageByPath[filePath] = p
		}
	}

	// For each package, try to find references to other packages
	for i := range pkgs {
		p := &pkgs[i]
		metadata, ok := p.Metadata.(pkg.NixStoreEntry)
		if !ok {
			continue
		}

		// Scan for references using the derivation file if available
		if metadata.DeriverPath != "" {
			refs, err := findReferencesInDerivation(metadata.DeriverPath, packageByStorePath)
			if err == nil {
				relationships = append(relationships, refs...)
			}
		}

		// Scan for references within the package files
		if len(metadata.Files) > 0 {
			refs, err := findReferencesInFiles(metadata.Files, p, packageByStorePath)
			if err == nil {
				relationships = append(relationships, refs...)
			}
		}
	}

	return relationships, nil
}

// findReferencesInDerivation tries to extract dependencies from a derivation file
func findReferencesInDerivation(drvPath string, packageByPath map[string]*pkg.Package) ([]artifact.Relationship, error) {
	var relationships []artifact.Relationship

	// Read the derivation file contents
	content, err := os.ReadFile(drvPath)
	if err != nil {
		return nil, err
	}

	// Look for store paths in the derivation file
	storePathPattern := regexp.MustCompile(`/nix/store/[a-z0-9]{32}-[^"'\s]+`)
	matches := storePathPattern.FindAllString(string(content), -1)

	// Unique matches
	uniquePaths := make(map[string]struct{})
	for _, match := range matches {
		uniquePaths[match] = struct{}{}
	}

	// Create relationships for found dependencies
	for path := range uniquePaths {
		depPkg, exists := packageByPath[path]
		if !exists {
			continue
		}

		// Skip self-references
		fromMeta, ok := depPkg.Metadata.(pkg.NixStoreEntry)
		if !ok || fromMeta.Path == drvPath {
			continue
		}

		// Add the dependency relationship
		pkg, exists := packageByPath[drvPath]
		if !exists {
			continue
		}

		relationships = append(relationships, artifact.Relationship{
			From: *pkg,
			To:   *depPkg,
			Type: artifact.DependencyOfRelationship,
			Data: map[string]string{"dependencyType": "buildtime"},
		})
	}

	return relationships, nil
}

// findReferencesInFiles looks for references to other packages within file contents
func findReferencesInFiles(files []string, fromPkg *pkg.Package, packageByPath map[string]*pkg.Package) ([]artifact.Relationship, error) {
	var relationships []artifact.Relationship
	uniqueRefs := make(map[string]struct{})

	// Limit search to a reasonable number of files to avoid performance issues
	maxFiles := 10
	fileCount := 0

	for _, file := range files {
		if fileCount >= maxFiles {
			break
		}

		// Skip files that are too large
		info, err := os.Stat(file)
		if err != nil || info.Size() > 1024*1024 {
			continue
		}

		// Skip directories
		if info.IsDir() {
			continue
		}

		// Look for binary files that might have references
		if isBinary(file) {
			fileCount++
			refs, err := findReferencesInBinary(file)
			if err != nil {
				continue
			}

			for _, ref := range refs {
				uniqueRefs[ref] = struct{}{}
			}
		}
	}

	// Create relationships for found dependencies
	for path := range uniqueRefs {
		depPkg, exists := packageByPath[path]
		if !exists {
			continue
		}

		// Skip self-references
		fromMeta, ok := fromPkg.Metadata.(pkg.NixStoreEntry)
		if !ok || fromMeta.Path == path {
			continue
		}

		relationships = append(relationships, artifact.Relationship{
			From: *fromPkg,
			To:   *depPkg,
			Type: artifact.DependencyOfRelationship,
			Data: map[string]string{"dependencyType": "runtime"},
		})
	}

	return relationships, nil
}

// Helper functions

// isBinary returns true if the file appears to be a binary
func isBinary(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".so" || ext == ".dylib" || ext == ".a" ||
		strings.HasSuffix(path, ".so.1") ||
		strings.Contains(path, ".so.")
}

// findReferencesInBinary extracts Nix store references from binary files
func findReferencesInBinary(path string) ([]string, error) {
	var references []string

	// Use string search instead of executing nix-store
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Search for store paths in the binary
	storePathPattern := regexp.MustCompile(`/nix/store/[a-z0-9]{32}-[^\\:\*\?"<>\|\x00-\x1F]+`)
	matches := storePathPattern.FindAll(data, -1)

	for _, match := range matches {
		references = append(references, string(match))
	}

	return references, nil
}
