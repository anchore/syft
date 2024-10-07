package rust

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/rust/internal/cargo"
)

type cargoModCataloger struct {
	config            CargoLockCatalogerConfig
	lockEntryHydrator cargo.LockEntryHydrator
}

func newCargoModCataloger(config CargoLockCatalogerConfig) *cargoModCataloger {
	return &cargoModCataloger{
		config:            config,
		lockEntryHydrator: cargo.NewLockEntryHydrator(config.SearchRemote),
	}
}

// parseCargoLock is a parser function for Cargo.lock contents, returning all rust cargo crates discovered.
func (c cargoModCataloger) parseCargoLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	m, err := cargo.ParseLockToml(reader, c.lockEntryHydrator)
	if err != nil {
		return nil, nil, err
	}

	var pkgs []pkg.Package

	var relationships []artifact.Relationship
	for _, p := range m.Packages {
		spkg := newPackageFromCargoMetadata(
			p,
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)

		// relationships = append(relationships, populatePackageContainsRelationships(spkg, p.CrateInfo)...)

		pkgs = append(pkgs, spkg)
	}

	return pkgs, relationships, nil
}

// TODO: this is fundamentally breaking the assumptions of what a file coordinate is, which is always relative to the artifact in some way
//
//	func populatePackageContainsRelationships(p pkg.Package, gen *cargo.CrateInfo) (relationships []artifact.Relationship) {
//		if gen == nil {
//			return nil
//		}
//		for path, h := range gen.PathSha1Hashes {
//			relationships = append(relationships, artifact.Relationship{
//				From: p,
//				To:   file.NewCoordinates(path, gen.DownloadLink),
//				Type: artifact.ContainsRelationship,
//				Data: file.Digest{
//					Algorithm: "sha1",
//					Value:     strings.ToLower(hex.EncodeToString(h[:])),
//				},
//			})
//		}
//		return relationships
//	}
