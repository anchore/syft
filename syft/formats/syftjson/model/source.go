package model

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/anchore/syft/syft/source"
)

type SourceType string

// TODO: let's try to use the reflect type approach for this

const (
	DirectorySourceType SourceType = "directory"
	FileSourceType      SourceType = "file"
	ImageSourceType     SourceType = "image"
)

func AllSourceTypes() []SourceType {
	return []SourceType{
		DirectorySourceType,
		FileSourceType,
		ImageSourceType,
	}
}

// Source object represents the thing that was cataloged
type Source struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Version  string      `json:"version"`
	Type     SourceType  `json:"type"`
	Metadata interface{} `json:"metadata"`
}

// sourceUnpacker is used to unmarshal Source objects
type sourceUnpacker struct {
	ID       string          `json:"id,omitempty"`
	Type     string          `json:"type"`
	Name     string          `json:"name"`
	Version  string          `json:"version"`
	Metadata json.RawMessage `json:"metadata"`
	Target   json.RawMessage `json:"target"` // pre-v9 schema support
}

// UnmarshalJSON populates a source object from JSON bytes.
func (s *Source) UnmarshalJSON(b []byte) error {
	var unpacker sourceUnpacker
	err := json.Unmarshal(b, &unpacker)
	if err != nil {
		return err
	}

	s.Name = unpacker.Name
	s.Version = unpacker.Version
	s.Type = parseSourceType(unpacker.Type)
	s.ID = unpacker.ID

	if len(unpacker.Target) > 0 {
		s.Metadata, err = extractPreSchemaV9Metadata(s.Type, unpacker.Target)
		if err != nil {
			return fmt.Errorf("unable to extract pre-schema-v9 source metadata: %w", err)
		}
		return nil
	}

	switch s.Type {
	case DirectorySourceType:
		var payload source.DirectorySourceMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		s.Metadata = payload
	case FileSourceType:
		var payload source.FileSourceMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		s.Metadata = payload

	case ImageSourceType:
		var payload source.StereoscopeImageSourceMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		s.Metadata = payload

	default:
		return fmt.Errorf("unsupported package metadata type: %+v", s.Type)
	}

	return nil
}

func extractPreSchemaV9Metadata(t SourceType, target []byte) (interface{}, error) {
	switch t {
	case DirectorySourceType:
		cleanTarget, err := strconv.Unquote(string(target))
		if err != nil {
			cleanTarget = string(target)
		}

		return source.DirectorySourceMetadata{
			Path: cleanTarget,
		}, nil

	case FileSourceType:
		cleanTarget, err := strconv.Unquote(string(target))
		if err != nil {
			cleanTarget = string(target)
		}

		return source.FileSourceMetadata{
			Path: cleanTarget,
		}, nil

	case ImageSourceType:
		var payload source.StereoscopeImageSourceMetadata
		if err := json.Unmarshal(target, &payload); err != nil {
			return nil, err
		}
		return payload, nil

	default:
		return nil, fmt.Errorf("unsupported package metadata type: %+v", t)
	}
}

func parseSourceType(og string) SourceType {
	s := strings.ToLower(og)
	switch s {
	case "directory", "dir":
		return DirectorySourceType
	case "file":
		return FileSourceType
	case "image":
		return ImageSourceType
	}
	return SourceType(og)
}
