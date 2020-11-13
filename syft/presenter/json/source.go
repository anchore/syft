package json

import (
	"encoding/json"
	"fmt"

	"github.com/anchore/syft/syft/scope"
)

type Source struct {
	Type   string      `json:"type"`
	Target interface{} `json:"target"`
}

type SourceUnpacker struct {
	Type   string          `json:"type"`
	Target json.RawMessage `json:"target"`
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

func (s *Source) UnmarshalJSON(b []byte) error {
	var unpacker SourceUnpacker
	if err := json.Unmarshal(b, &unpacker); err != nil {
		return err
	}

	s.Type = unpacker.Type

	switch s.Type {
	case "image":
		var payload Image
		if err := json.Unmarshal(unpacker.Target, &payload); err != nil {
			return err
		}
		s.Target = payload
	default:
		return fmt.Errorf("unsupported package metadata type: %+v", s.Type)

	}

	return nil
}
