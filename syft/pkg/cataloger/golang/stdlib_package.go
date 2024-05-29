package golang

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func stdlibProcessor(pkgs []pkg.Package, relationships []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	compilerPkgs, newRelationships := stdlibPackageAndRelationships(pkgs)
	return append(pkgs, compilerPkgs...), append(relationships, newRelationships...), err
}

func stdlibPackageAndRelationships(pkgs []pkg.Package) ([]pkg.Package, []artifact.Relationship) {
	var goCompilerPkgs []pkg.Package
	var relationships []artifact.Relationship
	totalLocations := file.NewLocationSet()
	for _, goPkg := range pkgs {
		mValue, ok := goPkg.Metadata.(pkg.GolangBinaryBuildinfoEntry)
		if !ok {
			continue
		}

		// go binary packages should only contain a single location
		for _, location := range goPkg.Locations.ToSlice() {
			if totalLocations.Contains(location) {
				continue
			}

			stdLibPkg := newGoStdLib(mValue.GoCompiledVersion, goPkg.Locations)
			if stdLibPkg != nil {
				goCompilerPkgs = append(goCompilerPkgs, *stdLibPkg)
				totalLocations.Add(location)
			}

			relationships = append(relationships, artifact.Relationship{
				From: *stdLibPkg,
				To:   goPkg,
				Type: artifact.DependencyOfRelationship,
			})
		}
	}
	return goCompilerPkgs, relationships
}

func newGoStdLib(version string, location file.LocationSet) *pkg.Package {
	stdlibCpe, err := generateStdlibCpe(version)
	if err != nil {
		return nil
	}
	goCompilerPkg := &pkg.Package{
		Name:      "stdlib",
		Version:   version,
		PURL:      packageURL("stdlib", strings.TrimPrefix(version, "go")),
		CPEs:      []cpe.CPE{stdlibCpe},
		Locations: location,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("BSD-3-Clause")),
		Language:  pkg.Go,
		Type:      pkg.GoModulePkg,
		Metadata: pkg.GolangBinaryBuildinfoEntry{
			GoCompiledVersion: version,
		},
	}
	goCompilerPkg.SetID()

	return goCompilerPkg
}

func generateStdlibCpe(version string) (stdlibCpe cpe.CPE, err error) {
	// GoCompiledVersion when pulled from a binary is prefixed by go
	version = strings.TrimPrefix(version, "go")

	// we also need to trim starting from the first +<metadata>  to
	// correctly extract potential rc candidate information for cpe generation
	// ex: 2.0.0-rc.1+build.123 -> 2.0.0-rc.1; if no + is found then + is returned
	after, _, found := strings.Cut("+", version)
	if found {
		version = after
	}

	// extracting <version> and <candidate>
	// https://regex101.com/r/985GsI/1
	captureGroups := internal.MatchNamedCaptureGroups(versionCandidateGroups, version)
	vr, ok := captureGroups["version"]
	if !ok || vr == "" {
		return stdlibCpe, fmt.Errorf("could not match candidate version for: %s", version)
	}

	cpeString := fmt.Sprintf("cpe:2.3:a:golang:go:%s:-:*:*:*:*:*:*", captureGroups["version"])
	if candidate, ok := captureGroups["candidate"]; ok && candidate != "" {
		cpeString = fmt.Sprintf("cpe:2.3:a:golang:go:%s:%s:*:*:*:*:*:*", vr, candidate)
	}

	return cpe.New(cpeString, cpe.GeneratedSource)
}
