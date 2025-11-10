package model

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/anchore/syft/internal/sourcemetadata"
	"github.com/anchore/syft/syft/source"
)

// Source represents the artifact that was analyzed to generate this SBOM, such as a container image, directory, or file archive.
// The Supplier field can be provided by users to fulfill NTIA minimum elements requirements.
type Source struct {
	// ID is a unique identifier for the analyzed source artifact.
	ID string `json:"id"`

	// Name is the name of the analyzed artifact (e.g., image name, directory path).
	Name string `json:"name"`

	// Version is the version of the analyzed artifact (e.g., image tag).
	Version string `json:"version"`

	// Supplier is supplier information, which can be user-provided for NTIA minimum elements compliance.
	Supplier string `json:"supplier,omitempty"`

	// Type is the source type (e.g., "image", "directory", "file").
	Type string `json:"type"`

	// Metadata contains additional source-specific metadata.
	Metadata interface{} `json:"metadata"`
}

// sourceUnpacker is used to unmarshal Source objects
type sourceUnpacker struct {
	ID       string          `json:"id,omitempty"`
	Name     string          `json:"name"`
	Version  string          `json:"version"`
	Supplier string          `json:"supplier,omitempty"`
	Type     string          `json:"type"`
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
	s.Supplier = unpacker.Supplier
	s.Type = unpacker.Type
	s.ID = unpacker.ID

	if len(unpacker.Target) > 0 {
		s.Type = cleanPreSchemaV9MetadataType(s.Type)
		s.Metadata, err = extractPreSchemaV9Metadata(s.Type, unpacker.Target)
		if err != nil {
			return fmt.Errorf("unable to extract pre-schema-v9 source metadata: %w", err)
		}
		return nil
	}

	return unpackSrcMetadata(s, unpacker)
}

func unpackSrcMetadata(s *Source, unpacker sourceUnpacker) error {
	rt := sourcemetadata.ReflectTypeFromJSONName(s.Type)
	if rt == nil {
		// in cases where we are converting from an SBOM without any source information, we don't want this to be fatal
		return nil
	}

	val := reflect.New(rt).Interface()
	if len(unpacker.Metadata) > 0 {
		if err := json.Unmarshal(unpacker.Metadata, val); err != nil {
			return err
		}
	}

	s.Metadata = reflect.ValueOf(val).Elem().Interface()

	return nil
}

func cleanPreSchemaV9MetadataType(t string) string {
	t = strings.ToLower(t)
	if t == "dir" {
		return "directory"
	}
	return t
}

func extractPreSchemaV9Metadata(t string, target []byte) (interface{}, error) {
	switch t {
	case "directory", "dir":
		cleanTarget, err := strconv.Unquote(string(target))
		if err != nil {
			cleanTarget = string(target)
		}

		return source.DirectoryMetadata{
			Path: cleanTarget,
		}, nil

	case "file":
		cleanTarget, err := strconv.Unquote(string(target))
		if err != nil {
			cleanTarget = string(target)
		}

		return source.FileMetadata{
			Path: cleanTarget,
		}, nil

	case "image":
		var payload source.ImageMetadata
		if err := json.Unmarshal(target, &payload); err != nil {
			return nil, err
		}
		return payload, nil

	default:
		return nil, fmt.Errorf("unsupported package metadata type: %+v", t)
	}
}
