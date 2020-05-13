package scope

import (
	"fmt"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/pkg/tree"
)

type Scope struct {
	Option Option
	Trees  []*tree.FileTree
}

func NewScope(img *image.Image, option Option) (Scope, error) {
	var trees = make([]*tree.FileTree, 0)

	if img == nil {
		return Scope{}, fmt.Errorf("no image given")
	}

	switch option {
	case SquashedScope:
		if img.SquashedTree == nil {
			return Scope{}, fmt.Errorf("the image does not have have a squashed tree")
		}
		trees = append(trees, img.SquashedTree)

	case AllLayersScope:
		if len(img.Layers) == 0 {
			return Scope{}, fmt.Errorf("the image does not contain any layers")
		}
		for _, layer := range img.Layers {
			trees = append(trees, layer.Tree)
		}
	default:
		return Scope{}, fmt.Errorf("bad option provided: %+v", option)
	}

	return Scope{
		Option: option,
		Trees:  trees,
	}, nil
}
