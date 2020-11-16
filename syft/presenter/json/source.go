package json

import (
	"encoding/json"
	"fmt"

	"github.com/anchore/syft/syft/source"
)

type Source struct {
	Type   string      `json:"type"`
	Target interface{} `json:"target"`
}

type SourceUnpacker struct {
	Type   string          `json:"type"`
	Target json.RawMessage `json:"target"`
}

func NewSource(src source.Metadata) (Source, error) {
	switch src.Scheme {
	case source.ImageScheme:
		return Source{
			Type:   "image",
			Target: src.ImageMetadata,
		}, nil
	case source.DirectoryScheme:
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
		var payload source.ImageMetadata
		if err := json.Unmarshal(unpacker.Target, &payload); err != nil {
			return err
		}
		s.Target = payload
	default:
		return fmt.Errorf("unsupported package metadata type: %+v", s.Type)

	}

	return nil
}

func (s *Source) ToSourceMetadata() source.Metadata {
	var metadata source.Metadata
	switch s.Type {
	case "directory":
		metadata.Scheme = source.DirectoryScheme
		metadata.Path = s.Target.(string)
	case "image":
		metadata.Scheme = source.ImageScheme
		metadata.ImageMetadata = s.Target.(source.ImageMetadata)
	}
	return metadata
}
