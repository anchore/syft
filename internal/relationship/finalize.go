package relationship

import (
	"github.com/anchore/syft/internal/relationship/binary"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

func Finalize(resolver file.Resolver, builder sbomsync.Builder, cfg cataloging.RelationshipsConfig, src artifact.Identifiable) {
	accessor := builder.(sbomsync.Accessor)

	// remove ELF packages and Binary packages that are already
	// represented by a source package (e.g. a package that is evident by some package manager)
	builder.DeletePackages(binary.PackagesToRemove(resolver, accessor)...)

	// add relationships showing packages that are evident by a file which is owned by another package (package-to-package)
	if cfg.PackageFileOwnershipOverlap {
		byFileOwnershipOverlapWorker(accessor)
	}

	// conditionally remove binary packages based on file ownership overlap relationships found
	// https://github.com/anchore/syft/issues/931
	if cfg.ExcludeBinaryPackagesWithFileOwnershipOverlap {
		excludeBinariesByFileOwnershipOverlap(accessor)
	}

	// add the new relationships for executables to the SBOM
	newBinaryRelationships := binary.NewDependencyRelationships(resolver, accessor)
	accessor.WriteToSBOM(func(s *sbom.SBOM) {
		s.Relationships = append(s.Relationships, newBinaryRelationships...)
	})
	builder.AddRelationships(newBinaryRelationships...)
	// add source "contains package" relationship (source-to-package)
	var sourceRelationships []artifact.Relationship
	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		sourceRelationships = toSource(src, s.Artifacts.Packages)
	})
	builder.AddRelationships(sourceRelationships...)

	// add evident-by relationships (package-to-file)
	var evidentByRelationships []artifact.Relationship
	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		evidentByRelationships = evidentBy(s.Artifacts.Packages)
	})

	builder.AddRelationships(evidentByRelationships...)
}
