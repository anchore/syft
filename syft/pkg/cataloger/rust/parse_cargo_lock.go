package rust

import (
	"context"
	"fmt"
	"github.com/anchore/syft/internal/log"
	"github.com/pelletier/go-toml/v2"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseCargoLock

type cargoLockFile struct {
	Version  int              `toml:"version"`
	Packages []CargoLockEntry `toml:"package"`
}

// parseCargoLock is a parser function for Cargo.lock contents, returning all rust cargo crates discovered.
func parseCargoLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	m := cargoLockFile{}
	err := toml.NewDecoder(reader).Decode(&m)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to load or parse Cargo.lock: %w", err)
	}

	var pkgs []pkg.Package
	var relationships []artifact.Relationship

	pkgName := make(map[string][]packageWrap)
	pkgMap := make(map[PackageID]packageWrap)

	for _, p := range m.Packages {
		p.CargoLockVersion = m.Version
		p.PackageID = PackageID{
			Name:    p.Name,
			Version: p.Version,
		}
		spkg := newPackageFromCargoMetadata(
			p,
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)
		pkgs = append(pkgs, spkg)
		wrappedPkg := packageWrap{
			spdxPackage: spkg,
			rustPackage: p,
		}
		pkgMap[p.PackageID] = wrappedPkg
		list, _ := pkgName[p.Name]
		if list == nil {
			pkgName[p.Name] = []packageWrap{wrappedPkg}
		} else {
			pkgName[p.Name] = append(list, wrappedPkg)
		}
	}

	for _, p := range pkgMap {
		log.Debugf("%s-%s deps: %s", p.rustPackage.Name, p.rustPackage.Version, p.rustPackage.Dependencies)
		for _, dep := range p.rustPackage.Dependencies {
			var depPkg packageWrap
			name, versionString, found := strings.Cut(dep, " ")
			if found {
				depPkg, found = pkgMap[PackageID{
					Name:    name,
					Version: versionString,
				}]
				if !found {
					log.Warn("A Dependency of a Dependency was not found. Not including in Relationships.")
					continue
				}
			} else {
				log.Debugf("%s-%s dep: name: %s, version: %s", p.rustPackage.Name, p.rustPackage.Version, name, versionString)
				depPkgs, ok := pkgName[name]
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

	return pkgs, relationships, nil
}
