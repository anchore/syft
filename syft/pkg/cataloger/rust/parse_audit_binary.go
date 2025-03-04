package rust

import (
	"context"
	"errors"
	"fmt"

	"github.com/rust-secure-code/go-rustaudit"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// Catalog identifies executables then attempts to read Rust dependency information from them
func parseAuditBinary(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	var relationships []artifact.Relationship

	unionReader, err := unionreader.GetUnionReader(reader.ReadCloser)
	if err != nil {
		return nil, nil, err
	}

	infos, err := parseAuditBinaryEntry(unionReader, reader.RealPath)
	for _, versionInfo := range infos {
		auditPkgs, auditRelationships := processAuditVersionInfo(reader.Location, versionInfo)
		pkgs = append(pkgs, auditPkgs...)
		relationships = append(relationships, auditRelationships...)
	}

	return pkgs, relationships, err
}

// scanFile scans file to try to report the Rust crate dependencies
func parseAuditBinaryEntry(reader unionreader.UnionReader, filename string) ([]rustaudit.VersionInfo, error) {
	// NOTE: multiple readers are returned to cover universal binaries, which are files
	// with more than one binary
	readers, err := unionreader.GetReaders(reader)
	if err != nil {
		log.Debugf("rust cataloger: failed to open a binary: %v", err)
		return nil, fmt.Errorf("rust cataloger: failed to open a binary: %w", err)
	}

	var versionInfos []rustaudit.VersionInfo
	for _, r := range readers {
		versionInfo, err := rustaudit.GetDependencyInfo(r)

		if err != nil {
			if errors.Is(err, rustaudit.ErrNoRustDepInfo) {
				// since the cataloger can only select executables and not distinguish if they are a Rust-compiled
				// binary, we should not show warnings/logs in this case.
				return nil, nil
			}
			log.Tracef("rust cataloger: unable to read dependency information (file=%q): %v", filename, err)
			return nil, fmt.Errorf("rust cataloger: unable to read dependency information: %w", err)
		}

		versionInfos = append(versionInfos, versionInfo)
	}

	return versionInfos, nil
}

// auditPkgPair is a helper struct to track the original index of the package in the original audit report + the syft package created for it
type auditPkgPair struct {
	pkg     *pkg.Package
	rustPkg rustaudit.Package
	index   int
}

func processAuditVersionInfo(location file.Location, versionInfo rustaudit.VersionInfo) ([]pkg.Package, []artifact.Relationship) {
	var pkgs []pkg.Package

	// first pass: create packages for all runtime dependencies (skip dev and invalid dependencies)
	pairsByOgIndex := make(map[int]auditPkgPair)
	for idx, dep := range versionInfo.Packages {
		p := newPackageFromAudit(&dep, location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
		pair := auditPkgPair{
			rustPkg: dep,
			index:   idx,
		}
		if pkg.IsValid(&p) && dep.Kind == rustaudit.Runtime {
			pkgs = append(pkgs, p)
			pair.pkg = &pkgs[len(pkgs)-1]
		}
		pairsByOgIndex[idx] = pair
	}

	// second pass: create relationships between any packages created
	// we have all the original audit package indices + info, but not all audit packages will have syft packages.
	// we need to be careful to not create relationships for packages that were not created.
	var rels []artifact.Relationship
	for _, parentPair := range pairsByOgIndex {
		// the rust-audit report lists dependencies by index from the original version info object. We need to find
		// the syft packages created for each listed dependency from that original object.
		for _, ogPkgIndex := range parentPair.rustPkg.Dependencies {
			if ogPkgIndex >= uint(len(versionInfo.Packages)) {
				log.WithFields("pkg", parentPair.pkg).Trace("cargo audit dependency index out of range: %d", ogPkgIndex)
				continue
			}
			depPair, ok := pairsByOgIndex[int(ogPkgIndex)]
			if !ok {
				log.WithFields("pkg", parentPair.pkg).Trace("cargo audit dependency not found: %d", ogPkgIndex)
				continue
			}

			if depPair.pkg == nil || parentPair.pkg == nil {
				// skip relationships for syft packages that were not created from the original report (no matter the reason)
				continue
			}

			rels = append(rels, artifact.Relationship{
				From: *depPair.pkg,
				To:   *parentPair.pkg,
				Type: artifact.DependencyOfRelationship,
			})
		}
	}

	relationship.Sort(rels)

	return pkgs, rels
}
