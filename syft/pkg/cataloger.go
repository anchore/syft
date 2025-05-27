package pkg

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
)

// Cataloger describes behavior for an object to participate in parsing container image or file system
// contents for the purpose of discovering Packages. Each concrete implementation should focus on discovering Packages
// for a specific Package Type or ecosystem.
type Cataloger interface {
	// Name returns a string that uniquely describes a cataloger
	Name() string
	// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing the catalog source.
	Catalog(context.Context, file.Resolver) ([]Package, []artifact.Relationship, error)
}

// CatalogerWithRelease is a Cataloger that can be configured with a Linux release. Every implementation built around the GenericCataloger should return
// this interface, where the caller can set the release, but every input should accept only the Cataloger interface, to maintain backwards compatibility.
type CatalogerWithRelease interface {
	Cataloger
	WithRelease(release *linux.Release) CatalogerWithRelease
}
