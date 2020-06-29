package scope

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/scope/resolvers"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

type FileContentResolver interface {
	ContentResolver
	FileResolver
}

type ContentResolver interface {
	MultipleFileContentsByRef(f ...file.Reference) (map[file.Reference]string, error)
}

type FileResolver interface {
	FilesByPath(paths ...file.Path) ([]file.Reference, error)
	FilesByGlob(patterns ...string) ([]file.Reference, error)
}

func getFileResolver(img *image.Image, option Option) (FileResolver, error) {
	switch option {
	case SquashedScope:
		return resolvers.NewImageSquashResolver(img)
	case AllLayersScope:
		return resolvers.NewAllLayersResolver(img)
	default:
		return nil, fmt.Errorf("bad option provided: %+v", option)
	}
}
