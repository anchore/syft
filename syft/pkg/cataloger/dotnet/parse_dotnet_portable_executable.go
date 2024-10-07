package dotnet

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/saferwall/pe"

	version "github.com/anchore/go-version"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseDotnetPortableExecutable

func parseDotnetPortableExecutable(_ context.Context, _ file.Resolver, _ *generic.Environment, f file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	by, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read file: %w", err)
	}

	peFile, err := pe.NewBytes(by, &pe.Options{})
	if err != nil {
		log.Tracef("unable to create PE instance for file '%s': %v", f.RealPath, err)
		return nil, nil, err
	}

	err = peFile.Parse()
	if err != nil {
		log.Tracef("unable to parse PE file '%s': %v", f.RealPath, err)
		return nil, nil, err
	}

	versionResources, err := peFile.ParseVersionResources()
	if err != nil {
		log.Tracef("unable to parse version resources in PE file: %s: %v", f.RealPath, err)
		return nil, nil, fmt.Errorf("unable to parse version resources in PE file: %w", err)
	}

	dotNetPkg, err := buildDotNetPackage(versionResources, f)
	if err != nil {
		log.Tracef("unable to build dotnet package for: %v %v", f.RealPath, err)
		return nil, nil, err
	}

	return []pkg.Package{dotNetPkg}, nil, nil
}

func buildDotNetPackage(versionResources map[string]string, f file.LocationReadCloser) (dnpkg pkg.Package, err error) {
	name := findName(versionResources)
	if name == "" {
		return dnpkg, fmt.Errorf("unable to find PE name in file")
	}

	version := findVersion(versionResources)
	if version == "" {
		return dnpkg, fmt.Errorf("unable to find PE version in file")
	}

	metadata := pkg.DotnetPortableExecutableEntry{
		AssemblyVersion: versionResources["Assembly Version"],
		LegalCopyright:  versionResources["LegalCopyright"],
		Comments:        versionResources["Comments"],
		InternalName:    versionResources["InternalName"],
		CompanyName:     versionResources["CompanyName"],
		ProductName:     versionResources["ProductName"],
		ProductVersion:  versionResources["ProductVersion"],
	}

	dnpkg = pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(f.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Type:      pkg.DotnetPkg,
		Language:  pkg.Dotnet,
		PURL:      portableExecutablePackageURL(name, version),
		Metadata:  metadata,
	}

	dnpkg.SetID()

	return dnpkg, nil
}

func portableExecutablePackageURL(name, version string) string {
	return packageurl.NewPackageURL(
		packageurl.TypeNuget, // See explanation in syft/pkg/cataloger/dotnet/package.go as to why this was chosen.
		"",
		name,
		version,
		nil,
		"",
	).ToString()
}

func extractVersion(version string) string {
	version = strings.TrimSpace(version)

	out := ""

	// some example versions are: "1, 0, 0, 0", "Release 73" or "4.7.4076.0 built by: NET472REL1LAST_B"
	// so try to split it and take the first parts that look numeric
	for i, f := range strings.Fields(version) {
		// if the output already has a number but the current segment does not have a number,
		// return what we found for the version
		if containsNumber(out) && !containsNumber(f) {
			return out
		}

		if i == 0 {
			out = f
		} else {
			out += " " + f
		}
	}

	return out
}

func keepGreaterSemanticVersion(productVersion string, fileVersion string) string {
	semanticProductVersion, err := version.NewVersion(productVersion)

	if err != nil || semanticProductVersion == nil {
		log.Tracef("Unable to create semantic version from portable executable product version %s", productVersion)
		return ""
	}

	semanticFileVersion, err := version.NewVersion(fileVersion)

	if err != nil || semanticFileVersion == nil {
		log.Tracef("Unable to create semantic version from portable executable file version %s", fileVersion)
		return productVersion
	}

	// Make no choice when they are semantically equal so that it falls
	// through to the other comparison cases
	if semanticProductVersion.Equal(semanticFileVersion) {
		return ""
	}

	if semanticFileVersion.GreaterThan(semanticProductVersion) {
		return fileVersion
	}

	return productVersion
}

func findVersion(versionResources map[string]string) string {
	productVersion := extractVersion(versionResources["ProductVersion"])
	fileVersion := extractVersion(versionResources["FileVersion"])

	semanticVersionCompareResult := keepGreaterSemanticVersion(productVersion, fileVersion)

	if semanticVersionCompareResult != "" {
		return semanticVersionCompareResult
	}

	productVersionDetail := punctuationCount(productVersion)
	fileVersionDetail := punctuationCount(fileVersion)

	if containsNumber(productVersion) && productVersionDetail >= fileVersionDetail {
		return productVersion
	}

	if containsNumber(fileVersion) && fileVersionDetail > 0 {
		return fileVersion
	}

	if containsNumber(productVersion) {
		return productVersion
	}

	if containsNumber(fileVersion) {
		return fileVersion
	}

	return productVersion
}

func containsNumber(s string) bool {
	return numberRegex.MatchString(s)
}

func punctuationCount(s string) int {
	return len(versionPunctuationRegex.FindAllString(s, -1))
}

var (
	// spaceRegex includes nbsp (#160) considered to be a space character
	spaceRegex              = regexp.MustCompile(`[\s\xa0]+`)
	numberRegex             = regexp.MustCompile(`\d`)
	versionPunctuationRegex = regexp.MustCompile(`[.,]+`)
)

func findName(versionResources map[string]string) string {
	// PE files found in the wild _not_ authored by Microsoft seem to use ProductName as a clear
	// identifier of the software
	nameFields := []string{"ProductName", "FileDescription", "InternalName", "OriginalFilename"}

	if isMicrosoft(versionResources) {
		// Microsoft seems to be consistent using the FileDescription, with a few that are blank and have
		// fallbacks to ProductName last, as this is often something very broad like "Microsoft Windows"
		nameFields = []string{"FileDescription", "InternalName", "OriginalFilename", "ProductName"}
	}

	for _, field := range nameFields {
		value := spaceNormalize(versionResources[field])
		if value == "" {
			continue
		}
		return value
	}

	return ""
}

// normalizes a string to a trimmed version with all contigous whitespace collapsed to a single space character
func spaceNormalize(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	// ensure valid utf8 text
	value = strings.ToValidUTF8(value, "")
	// consolidate all space characters
	value = spaceRegex.ReplaceAllString(value, " ")
	// remove other non-space, non-printable characters
	value = regexp.MustCompile(`[\x00-\x1f]`).ReplaceAllString(value, "")
	// consolidate all space characters again in case other non-printables were in-between
	value = spaceRegex.ReplaceAllString(value, " ")
	// finally, remove any remaining surrounding whitespace
	value = strings.TrimSpace(value)
	return value
}

func isMicrosoft(versionResources map[string]string) bool {
	return strings.Contains(strings.ToLower(versionResources["CompanyName"]), "microsoft") ||
		strings.Contains(strings.ToLower(versionResources["ProductName"]), "microsoft")
}
