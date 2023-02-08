package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

var errUnknownMetadataType = errors.New("unknown metadata type")

// Package represents a pkg.Package object specialized for JSON marshaling and unmarshalling.
type Package struct {
	PackageBasicData
	PackageCustomData
}

// PackageBasicData contains non-ambiguous values (type-wise) from pkg.Package.
type PackageBasicData struct {
	ID        string                  `json:"id"`
	Name      string                  `json:"name"`
	Version   string                  `json:"version"`
	Type      pkg.Type                `json:"type"`
	FoundBy   string                  `json:"foundBy"`
	Locations []source.Coordinates    `json:"locations"`
	Licenses  internal.LogicalStrings `json:"licenses"`
	Language  pkg.Language            `json:"language"`
	CPEs      []string                `json:"cpes"`
	PURL      string                  `json:"purl"`
}

// PackageCustomData contains ambiguous values (type-wise) from pkg.Package.
type PackageCustomData struct {
	MetadataType pkg.MetadataType `json:"metadataType,omitempty"`
	Metadata     interface{}      `json:"metadata,omitempty"`
}

// packageMetadataUnpacker is all values needed from Package to disambiguate ambiguous fields during json unmarshaling.
type packageMetadataUnpacker struct {
	MetadataType pkg.MetadataType `json:"metadataType"`
	Metadata     json.RawMessage  `json:"metadata"`
}

func (p *packageMetadataUnpacker) String() string {
	return fmt.Sprintf("metadataType: %s, metadata: %s", p.MetadataType, string(p.Metadata))
}

// UnmarshalJSON is a custom unmarshaller for handling basic values and values with ambiguous types.
func (p *Package) UnmarshalJSON(b []byte) error {
	var basic PackageBasicData
	if err := json.Unmarshal(b, &basic); err != nil {
		return err
	}
	p.PackageBasicData = basic

	var unpacker packageMetadataUnpacker
	if err := json.Unmarshal(b, &unpacker); err != nil {
		log.Warnf("failed to unmarshall into packageMetadataUnpacker: %v", err)
		return err
	}

	err := unpackMetadata(p, unpacker)
	if errors.Is(err, errUnknownMetadataType) {
		log.Warnf("unknown package metadata type=%q for packageID=%q", p.MetadataType, p.ID)
		return nil
	}

	return err
}

func unpackMetadata(p *Package, unpacker packageMetadataUnpacker) error {
	p.MetadataType = pkg.CleanMetadataType(unpacker.MetadataType)

	typ, ok := pkg.MetadataTypeByName[p.MetadataType]
	if ok {
		val := reflect.New(typ).Interface()
		if len(unpacker.Metadata) > 0 {
			if err := json.Unmarshal(unpacker.Metadata, val); err != nil {
				return err
			}
		}
		p.Metadata = reflect.ValueOf(val).Elem().Interface()
		return nil
	}

	// capture unknown metadata as a generic struct
	if len(unpacker.Metadata) > 0 {
		var val interface{}
		if err := json.Unmarshal(unpacker.Metadata, &val); err != nil {
			return err
		}
		p.Metadata = val
	}

	if p.MetadataType != "" {
		return errUnknownMetadataType
	}

	return nil
}
