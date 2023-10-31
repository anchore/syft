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
		return nil, nil, fmt.Errorf("unable to create PE file instance: %w", err)
	}

	err = peFile.Parse()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse PE file: %w", err)
	}

	versionResources, err := peFile.ParseVersionResources()
	if err != nil {
		// this is not a fatal error, just log and continue
		// TODO: consider this case for "known unknowns" (same goes for cases below)
		log.Tracef("unable to parse version resources in PE file: %s", f.RealPath)
		return nil, nil, nil
	}

	name := findName(versionResources)
	if name == "" {
		log.Tracef("unable to find FileDescription, or ProductName in PE file: %s", f.RealPath)
		return nil, nil, nil
	}

	version := findVersion(versionResources)
	if strings.TrimSpace(version) == "" {
		log.Tracef("unable to find FileVersion in PE file: %s", f.RealPath)
		return nil, nil, nil
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

	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(f.Location),
		Type:      pkg.DotnetPkg,
		PURL:      purl,
		Metadata:  metadata,
	}

	p.SetID()

	return []pkg.Package{p}, nil, nil
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
