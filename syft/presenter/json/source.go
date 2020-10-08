package json

import (
	"fmt"

	"github.com/anchore/syft/syft/scope"
)

type Source struct {
	Type   string      `json:"type"`
	Target interface{} `json:"target"`
}

func NewSource(s scope.Scope) (Source, error) {
	switch src := s.Source.(type) {
	case scope.ImageSource:
		return Source{
			Type:   "image",
			Target: NewImage(src),
		}, nil
	case scope.DirSource:
		return Source{
			Type:   "directory",
			Target: src.Path,
		}, nil
	default:
		return Source{}, fmt.Errorf("unsupported source: %T", src)
	}
}
