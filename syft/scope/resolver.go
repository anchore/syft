package scope

import (
	"fmt"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/scope/resolvers"
)

type Resolver interface {
	ContentResolver
	FileResolver
}

// ContentResolver knows how to get content from file.References
type ContentResolver interface {
	MultipleFileContentsByRef(f ...file.Reference) (map[file.Reference]string, error)
}

//  FileResolver knows how to get file.References from string paths and globs
type FileResolver interface {
	FilesByPath(paths ...file.Path) ([]file.Reference, error)
	FilesByGlob(patterns ...string) ([]file.Reference, error)
}

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
