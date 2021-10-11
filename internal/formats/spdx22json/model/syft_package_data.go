package model

import (
	"encoding/json"
	"fmt"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type SyftPackageData struct {
	SyftPackageBasicData
	SyftPackageCustomData
}

type SyftPackageCustomData struct {
	MetadataType pkg.MetadataType `json:"metadataType"`
	Metadata     interface{}      `json:"metadata"`
}

type SyftPackageBasicData struct {
	PackageType pkg.Type          `json:"type"`
	FoundBy     string            `json:"foundBy"`
	Locations   []source.Location `json:"locations"`
	Licenses    []string          `json:"licenses"`
	Language    pkg.Language      `json:"language"`
}

// syftPackageMetadataUnpacker is all values needed from Package to disambiguate ambiguous fields during json unmarshaling.
type syftPackageMetadataUnpacker struct {
	MetadataType pkg.MetadataType `json:"metadataType"`
	Metadata     json.RawMessage  `json:"metadata"`
}

func (p *syftPackageMetadataUnpacker) String() string {
	return fmt.Sprintf("metadataType: %s, metadata: %s", p.MetadataType, string(p.Metadata))
}

// UnmarshalJSON is a custom unmarshaller for handling basic values and values with ambiguous types.
func (p *SyftPackageData) UnmarshalJSON(b []byte) error {
	var basic SyftPackageBasicData
	if err := json.Unmarshal(b, &basic); err != nil {
		return err
	}
	p.SyftPackageBasicData = basic

	var unpacker syftPackageMetadataUnpacker
	if err := json.Unmarshal(b, &unpacker); err != nil {
		log.Warnf("failed to unmarshall into syftPackageMetadataUnpacker: %v", err)
		return err
	}

	p.MetadataType = unpacker.MetadataType

	switch p.MetadataType {
	case pkg.ApkMetadataType:
		var payload pkg.ApkMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		p.Metadata = payload
	case pkg.RpmdbMetadataType:
		var payload pkg.RpmdbMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		p.Metadata = payload
	case pkg.DpkgMetadataType:
		var payload pkg.DpkgMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		p.Metadata = payload
	case pkg.JavaMetadataType:
		var payload pkg.JavaMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		p.Metadata = payload
	case pkg.RustCargoPackageMetadataType:
		var payload pkg.CargoPackageMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		p.Metadata = payload
	case pkg.GemMetadataType:
		var payload pkg.GemMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		p.Metadata = payload
	case pkg.KbPackageMetadataType:
		var payload pkg.KbPackageMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		p.Metadata = payload
	case pkg.PythonPackageMetadataType:
		var payload pkg.PythonPackageMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		p.Metadata = payload
	case pkg.NpmPackageJSONMetadataType:
		var payload pkg.NpmPackageJSONMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		p.Metadata = payload
	}

	return nil
}
