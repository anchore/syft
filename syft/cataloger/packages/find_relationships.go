package packages

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func FindRelationships(catalog pkg.Collection, resolver file.Resolver) []artifact.Relationship {
	var allRelationships []artifact.Relationship
	for p := range catalog.Enumerate() {
		relationships, err := createFileOwnershipRelationships(p, resolver)
		if err != nil {
			log.Warnf("unable to create any package-file relationships for package name=%q: %w", p.Name, err)
			continue
		}
		allRelationships = append(allRelationships, relationships...)
	}

	allRelationships = append(allRelationships, findOwnershipByFileOverlapRelationship(catalog)...)

	return allRelationships
}
