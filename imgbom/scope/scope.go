package scope

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/scope/resolvers"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

type ImageSource struct {
	Img *image.Image
}

type DirSource struct {
	Path string
}

type Scope struct {
	Option   Option
	resolver Resolver
	ImgSrc   ImageSource
	DirSrc   DirSource
}

func NewScopeFromDir(path string, option Option) (Scope, error) {
	return Scope{
		Option: option,
		resolver: &resolvers.DirectoryResolver{
			Path: path,
		},
		DirSrc: DirSource{
			Path: path,
		},
	}, nil
}

func NewScopeFromImage(img *image.Image, option Option) (Scope, error) {
	if img == nil {
		return Scope{}, fmt.Errorf("no image given")
	}

	resolver, err := getImageResolver(img, option)
	if err != nil {
		return Scope{}, fmt.Errorf("could not determine file resolver: %w", err)
	}

	return Scope{
		Option:   option,
		resolver: resolver,
		ImgSrc: ImageSource{
			Img: img,
		},
	}, nil
}

func (s Scope) FilesByPath(paths ...file.Path) ([]file.Reference, error) {
	return s.resolver.FilesByPath(paths...)
}

func (s Scope) FilesByGlob(patterns ...string) ([]file.Reference, error) {
	return s.resolver.FilesByGlob(patterns...)
}

func (s Scope) MultipleFileContentsByRef(f ...file.Reference) (map[file.Reference]string, error) {
	return s.resolver.MultipleFileContentsByRef(f...)
}

// return either a dir source or img source
func (s Scope) Source() interface{} {
	if s.ImgSrc != (ImageSource{}) {
		return s.ImgSrc
	}
	if s.DirSrc != (DirSource{}) {
		return s.DirSrc
	}

	return nil
}
