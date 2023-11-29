package dotnet

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/saferwall/pe"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseDotnetPortableExecutable

func parseDotnetPortableExecutable(_ file.Resolver, _ *generic.Environment, f file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	by, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read file: %w", err)
	}

	peFile, err := pe.NewBytes(by, &pe.Options{})
	if err != nil {
		// TODO: known-unknown
		log.Tracef("unable to create PE instance for file '%s': %v", f.RealPath, err)
		return nil, nil, nil
	}

	err = peFile.Parse()
	if err != nil {
		// TODO: known-unknown
		log.Tracef("unable to parse PE file '%s': %v", f.RealPath, err)
		return nil, nil, nil
	}

	versionResources, err := peFile.ParseVersionResources()
	if err != nil {
		// TODO: known-unknown
		log.Tracef("unable to parse version resources in PE file: %s: %v", f.RealPath, err)
		return nil, nil, nil
	}

	dotNetPkg, err := buildDotNetPackage(versionResources, f)
	if err != nil {
		// TODO: known-unknown
		log.Tracef("unable to build dotnet package: %v", err)
		return nil, nil, nil
	}

	return []pkg.Package{dotNetPkg}, nil, nil
}

func buildDotNetPackage(versionResources map[string]string, f file.LocationReadCloser) (dnpkg pkg.Package, err error) {
	name := findName(versionResources)
	if name == "" {
		return dnpkg, fmt.Errorf("unable to find FileDescription, or ProductName in PE file: %s", f.RealPath)
	}

	version := findVersion(versionResources)
	if strings.TrimSpace(version) == "" {
		return dnpkg, fmt.Errorf("unable to find FileVersion in PE file: %s", f.RealPath)
	}

	purl := packageurl.NewPackageURL(
		packageurl.TypeNuget, // See explanation in syft/pkg/cataloger/dotnet/package.go as to why this was chosen.
		"",
		name,
		version,
		nil,
		"",
	).ToString()

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
		PURL:      purl,
		Metadata:  metadata,
	}

	dnpkg.SetID()

	return dnpkg, nil
}

func findVersion(versionResources map[string]string) string {
	for _, key := range []string{"FileVersion"} {
		if version, ok := versionResources[key]; ok {
			if strings.TrimSpace(version) == "" {
				continue
			}
			fields := strings.Fields(version)
			if len(fields) > 0 {
				return fields[0]
			}
		}
	}
	return ""
}

func findName(versionResources map[string]string) string {
	for _, key := range []string{"FileDescription", "ProductName"} {
		if name, ok := versionResources[key]; ok {
			if strings.TrimSpace(name) == "" {
				continue
			}
			trimmed := strings.TrimSpace(name)
			return regexp.MustCompile(`[^a-zA-Z0-9.]+`).ReplaceAllString(trimmed, "")
		}
	}
	return ""
}
