package pkg

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
)

// Cataloger describes behavior for an object to participate in parsing container image or file system
// contents for the purpose of discovering Packages. Each concrete implementation should focus on discovering Packages
// for a specific Package Type or ecosystem.
type Cataloger interface {
	// Name returns a string that uniquely describes a cataloger
	Name() string
	// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing the catalog source.
	Catalog(resolver file.Resolver) ([]Package, []artifact.Relationship, error)
}
