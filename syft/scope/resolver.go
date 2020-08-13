package scope

import (
	"fmt"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/scope/resolvers"
)

// Resolver is an interface that encompasses how to get specific file references and file contents for a generic data source.
type Resolver interface {
	ContentResolver
	FileResolver
}

// ContentResolver knows how to get file content for given file.References
type ContentResolver interface {
	MultipleFileContentsByRef(f ...file.Reference) (map[file.Reference]string, error)
}

//  FileResolver knows how to get file.References for given string paths and globs
type FileResolver interface {
	FilesByPath(paths ...file.Path) ([]file.Reference, error)
	FilesByGlob(patterns ...string) ([]file.Reference, error)
}

// getImageResolver returns the appropriate resolve for a container image given the scope option
func getImageResolver(img *image.Image, option Option) (Resolver, error) {
	switch option {
	case SquashedScope:
		return resolvers.NewImageSquashResolver(img)
	case AllLayersScope:
		return resolvers.NewAllLayersResolver(img)
	default:
		return nil, fmt.Errorf("bad option provided: %+v", option)
	}
}
