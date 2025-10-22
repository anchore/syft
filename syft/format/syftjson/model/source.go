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

// Source object represents the thing that was cataloged
// Note: syft currently makes no claims or runs any logic to determine the Supplier field below

// Instead, the Supplier can be determined by the user of syft and passed as a config or flag to help fulfill
// the NTIA minimum elements. For mor information see the NTIA framing document below
// https://www.ntia.gov/files/ntia/publications/framingsbom_20191112.pdf
type Source struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Version  string      `json:"version"`
	Supplier string      `json:"supplier,omitempty"`
	Type     string      `json:"type"`
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
