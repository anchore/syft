package model

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/anchore/syft/syft/source"
)

// Source object represents the thing that was cataloged
type Source struct {
	ID     string      `json:"id"`
	Type   string      `json:"type"`
	Target interface{} `json:"target"`
}

// sourceUnpacker is used to unmarshal Source objects
type sourceUnpacker struct {
	ID     string          `json:"id,omitempty"`
	Type   string          `json:"type"`
	Target json.RawMessage `json:"target"`
}

// UnmarshalJSON populates a source object from JSON bytes.
func (s *Source) UnmarshalJSON(b []byte) error {
	var unpacker sourceUnpacker
	if err := json.Unmarshal(b, &unpacker); err != nil {
		return err
	}

	s.Type = unpacker.Type
	s.ID = unpacker.ID

	switch s.Type {
	case "directory", "file":
		if target, err := strconv.Unquote(string(unpacker.Target)); err == nil {
			s.Target = target
		} else {
			s.Target = string(unpacker.Target[:])
		}

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
