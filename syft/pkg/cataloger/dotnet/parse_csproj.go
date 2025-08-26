package dotnet

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// csprojProject represents the root element of a .csproj file
type csprojProject struct {
	XMLName        xml.Name              `xml:"Project"`
	Sdk            string                `xml:"Sdk,attr"`
	PropertyGroups []csprojPropertyGroup `xml:"PropertyGroup"`
	ItemGroups     []csprojItemGroup     `xml:"ItemGroup"`
}

// csprojPropertyGroup represents a PropertyGroup element containing MSBuild properties
type csprojPropertyGroup struct {
	Properties []csprojProperty `xml:",any"`
}

// csprojProperty represents any property within a PropertyGroup
type csprojProperty struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// csprojItemGroup represents an ItemGroup element containing references
type csprojItemGroup struct {
	PackageReferences []csprojPackageReference `xml:"PackageReference"`
	ProjectReferences []csprojProjectReference `xml:"ProjectReference"`
}

// csprojPackageReference represents a PackageReference element
type csprojPackageReference struct {
	Include       string `xml:"Include,attr"`
	Version       string `xml:"Version,attr"`
	PrivateAssets string `xml:"PrivateAssets,attr"`
	IncludeAssets string `xml:"IncludeAssets,attr"`
	Condition     string `xml:"Condition,attr"`
}

// csprojProjectReference represents a ProjectReference element
type csprojProjectReference struct {
	Include   string `xml:"Include,attr"`
	Condition string `xml:"Condition,attr"`
}

func parseDotnetCsproj(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read .csproj file: %w", err)
	}

	var project csprojProject
	if err := xml.Unmarshal(contents, &project); err != nil {
		return nil, nil, fmt.Errorf("unable to parse .csproj XML: %w", err)
	}

	// Build property map from PropertyGroups
	properties := buildPropertyMap(project.PropertyGroups)

	var pkgs []pkg.Package
	var relationships []artifact.Relationship

	// Process PackageReference elements
	for _, itemGroup := range project.ItemGroups {
		for _, pkgRef := range itemGroup.PackageReferences {
			// Skip packages that are build-time only or analyzers
			if shouldSkipPackageReference(pkgRef) {
				continue
			}

			// Resolve any MSBuild property variables in the version
			resolvedVersion := resolveProperties(pkgRef.Version, properties)
			pkgRef.Version = resolvedVersion

			p := buildPackageFromReference(pkgRef, reader.Location)
			if p != nil {
				pkgs = append(pkgs, *p)
			}
		}

		// Process ProjectReference elements (if we want to include them as relationships)
		for _, projRef := range itemGroup.ProjectReferences {
			// ProjectReferences represent internal project dependencies
			// We could create relationships here, but for now we skip them
			// since they represent source-to-source dependencies within the same solution
			_ = projRef
		}
	}

	return pkgs, relationships, nil
}

// shouldSkipPackageReference determines if a package reference should be skipped
func shouldSkipPackageReference(ref csprojPackageReference) bool {
	// Skip packages that are private assets only (build-time dependencies)
	if ref.PrivateAssets == "all" || ref.PrivateAssets == "All" {
		return true
	}

	// Skip conditional references that are likely build/development only
	condition := strings.ToLower(ref.Condition)
	if strings.Contains(condition, "debug") && !strings.Contains(condition, "release") {
		return true
	}

	// Skip packages that are commonly build-time only
	lowerName := strings.ToLower(ref.Include)
	buildTimePackages := map[string]bool{
		"microsoft.net.test.sdk":    true,
		"stylecop.analyzers":        true,
		"microsoft.codeanalysis":    true,
		"coverlet.collector":        true,
		"xunit.runner.visualstudio": true,
		"nunit":                     true,
		"nunit3testadapter":         true,
		"mstest.testadapter":        true,
		"mstest.testframework":      true,
	}

	for buildPkg := range buildTimePackages {
		if strings.Contains(lowerName, buildPkg) {
			return true
		}
	}

	return false
}

// buildPropertyMap creates a map of MSBuild properties from PropertyGroups
func buildPropertyMap(propertyGroups []csprojPropertyGroup) map[string]string {
	properties := make(map[string]string)

	for _, group := range propertyGroups {
		for _, prop := range group.Properties {
			propertyName := prop.XMLName.Local
			propertyValue := strings.TrimSpace(prop.Value)
			if propertyName != "" && propertyValue != "" {
				properties[propertyName] = propertyValue
			}
		}
	}

	return properties
}

// resolveProperties resolves MSBuild property variables like $(PropertyName) in a string
func resolveProperties(input string, properties map[string]string) string {
	if input == "" {
		return input
	}

	// Pattern matches $(PropertyName)
	propertyPattern := `\$\(([^)]+)\)`
	re := regexp.MustCompile(propertyPattern)

	result := re.ReplaceAllStringFunc(input, func(match string) string {
		// Extract property name from $(PropertyName)
		propertyName := match[2 : len(match)-1] // Remove $( and )

		if value, exists := properties[propertyName]; exists {
			return value
		}

		// Return original if property not found (preserve for debugging)
		return match
	})

	return result
}

// buildPackageFromReference creates a Package from a PackageReference element
func buildPackageFromReference(ref csprojPackageReference, location file.Location) *pkg.Package {
	name := strings.TrimSpace(ref.Include)
	if name == "" {
		return nil
	}

	version := strings.TrimSpace(ref.Version)
	// If version is empty, this might be a framework reference or implicit version
	// For now, we'll skip packages without explicit versions since we can't determine them
	// from the .csproj alone (would need props/targets files or lock files)
	if version == "" {
		return nil
	}

	// Skip packages with unresolved MSBuild properties (contains $(...))
	if strings.Contains(version, "$(") {
		return nil
	}

	// Generate PURL following the established pattern for .NET packages
	purl := packageurl.NewPackageURL(
		packageurl.TypeNuget,
		"",
		name,
		version,
		nil,
		"",
	)

	p := &pkg.Package{
		Name:      name,
		Version:   version,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		PURL:      purl.ToString(),
		Locations: file.NewLocationSet(location),
		Metadata: pkg.DotnetDepsEntry{
			Name:     name,
			Version:  version,
			Path:     filepath.Dir(location.RealPath),
			Sha512:   "",
			HashPath: "",
		},
	}

	return p
}
