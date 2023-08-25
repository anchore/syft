package dotnet

import (
	"fmt"
	"io"

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

	name := versionResources["FileDescription"]
	if name == "" {
		log.Tracef("unable to find FileDescription in PE file: %s", f.RealPath)
		return nil, nil, nil
	}

	version := versionResources["FileVersion"]
	if version == "" {
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

	metadata := pkg.DotnetPortableExecutableMetadata{
		AssemblyVersion: versionResources["Assembly Version"],
		LegalCopyright:  versionResources["LegalCopyright"],
		Comments:        versionResources["Comments"],
		InternalName:    versionResources["InternalName"],
		CompanyName:     versionResources["CompanyName"],
		ProductName:     versionResources["ProductName"],
		ProductVersion:  versionResources["ProductVersion"],
	}

	p := pkg.Package{
		Name:         name,
		Version:      version,
		Locations:    file.NewLocationSet(f.Location),
		Type:         pkg.DotnetPkg,
		PURL:         purl,
		MetadataType: pkg.DotnetPortableExecutableMetadataType,
		Metadata:     metadata,
	}

	p.SetID()

	return []pkg.Package{p}, nil, nil
}
