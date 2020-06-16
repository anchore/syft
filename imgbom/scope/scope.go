package scope

import (
	"fmt"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

type Scope struct {
	Option   Option
	resolver FileResolver
	Image    *image.Image
}

func NewScope(img *image.Image, option Option) (Scope, error) {
	if img == nil {
		return Scope{}, fmt.Errorf("no image given")
	}

	resolver, err := getFileResolver(img, option)
	if err != nil {
		return Scope{}, fmt.Errorf("could not determine file resolver: %w", err)
	}

	return Scope{
		Option:   option,
		resolver: resolver,
		Image:    img,
	}, nil
}

func (s Scope) FilesByPath(paths ...file.Path) ([]file.Reference, error) {
	return s.resolver.FilesByPath(paths...)
}

func (s Scope) FilesByGlob(patterns ...string) ([]file.Reference, error) {
	return s.resolver.FilesByGlob(patterns...)
}
