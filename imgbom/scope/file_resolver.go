package scope

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/scope/resolvers"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

type Resolver interface {
	ContentResolver // knows how to get content from file.References
	FileResolver    // knows how to get file.References from string paths and globs
}

type ContentResolver interface {
	MultipleFileContentsByRef(f ...file.Reference) (map[file.Reference]string, error)
}

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
