package rust

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg/rust"
	"github.com/pelletier/go-toml/v2"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseCargoLock

type packageWrap struct {
	spdxPackage pkg.Package
	rustPackage rust.RustCargoLockEntry
}

type cargoLockFile struct {
	Version  int                       `toml:"version"`
	Packages []rust.RustCargoLockEntry `toml:"package"`
}

// parseCargoLock is a parser function for Cargo.lock contents, returning all rust cargo crates discovered.
func parseCargoLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	m := cargoLockFile{}
	err := toml.NewDecoder(reader).Decode(&m)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to load or parse Cargo.lock: %w", err)
	}

	var pkgs []pkg.Package

	pkgName := make(map[string][]packageWrap)
	pkgMap := make(map[rust.PackageID]packageWrap)

	var relationships []artifact.Relationship
	for _, p := range m.Packages {
		p.CargoLockVersion = m.Version
		if p.Dependencies == nil {
			p.Dependencies = []string{}
		}

		var licenseSet = pkg.NewLicenseSet()
		gen, err := p.GetGeneratedInformation()
		if err == nil {
			if len(gen.Licenses) == 0 {
				log.Debugf("no licenses for %s-%s!", p.Name, p.Version)
			}
		} else {
			log.Warnf("error whilst generating info for %s-%s: %s", p.Name, p.Version, err)
		}
		for _, license := range gen.Licenses {
			log.Debugf("Got license %s for %s-%s", license, p.Name, p.Version)
			licenseSet.Add(pkg.NewLicense(license))
		}

		spkg := newPackageFromCargoMetadata(
			p,
			licenseSet,
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)

		relationships = append(relationships, populatePackageContainsRelationships(spkg, &gen)...)

		pkgs = append(pkgs, spkg)
		wrappedPkg := packageWrap{
			spdxPackage: spkg,
			rustPackage: p,
		}
		pkgMap[p.ToPackageID()] = wrappedPkg
		list, ok := pkgName[p.Name]
		if list == nil || !ok {
			pkgName[p.Name] = []packageWrap{wrappedPkg}
		} else {
			pkgName[p.Name] = append(list, wrappedPkg)
		}
	}

	relationships = append(relationships, populatePackageDependencyRelationships(&pkgName, &pkgMap)...)

	return pkgs, relationships, nil
}
func populatePackageContainsRelationships(p pkg.Package, gen *rust.GeneratedDepInfo) (relationships []artifact.Relationship) {
	for path, h := range gen.PathSha1Hashes {
		relationships = append(relationships, artifact.Relationship{
			From: p,
			To:   file.NewCoordinates(path, gen.DownloadLink),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     strings.ToLower(hex.EncodeToString(h[:])),
			},
		})
	}
	return relationships
}
func populatePackageDependencyRelationships(pkgName *map[string][]packageWrap, pkgMap *map[rust.PackageID]packageWrap) (relationships []artifact.Relationship) {
	for _, p := range *pkgMap {
		log.Debugf("%s-%s deps: %s", p.rustPackage.Name, p.rustPackage.Version, p.rustPackage.Dependencies)
		for _, dep := range p.rustPackage.Dependencies {
			var depPkg packageWrap
			name, versionString, found := strings.Cut(dep, " ")
			if found {
				depPkg, found = (*pkgMap)[rust.PackageID{
					Name:    name,
					Version: versionString,
				}]
				if !found {
					log.Warn("A Dependency of a Dependency was not found. Not including in Relationships.")
					continue
				}
			} else {
				log.Debugf("%s-%s dep: name: %s, version: %s", p.rustPackage.Name, p.rustPackage.Version, name, versionString)
				depPkgs, ok := (*pkgName)[name]
				if !ok || depPkgs == nil || len(depPkgs) == 0 {
					log.Warn("A Dependency of a Dependency was not found. Not including in Relationships.")
					continue
				}
				if len(depPkgs) > 1 {
					log.Warn("A Dependency was ambiguous. Not including in Relationships.")
					continue
				}
				depPkg = depPkgs[0]
			}
			log.Debugf("Adding dependency-of relationshop between %s-%s and %s-%s.", depPkg.rustPackage.Name, depPkg.rustPackage.Version, p.rustPackage.Name, p.rustPackage.Version)
			//Todo: is this the correct direction?
			relationships = append(relationships, artifact.Relationship{
				From: depPkg.spdxPackage,
				To:   p.spdxPackage,
				Type: artifact.DependencyOfRelationship,
			})
		}
	}
	return relationships
}
