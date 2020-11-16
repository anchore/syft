package json

import (
	"encoding/json"
	"fmt"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type Artifact struct {
	artifactBasicMetadata
	artifactCustomMetadata
}

type artifactBasicMetadata struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Type      pkg.Type          `json:"type"`
	FoundBy   string            `json:"foundBy"`
	Locations []source.Location `json:"locations"`
	Licenses  []string          `json:"licenses"`
	Language  pkg.Language      `json:"language"`
}

type artifactCustomMetadata struct {
	MetadataType pkg.MetadataType `json:"metadataType"`
	Metadata     interface{}      `json:"metadata,omitempty"`
}

type artifactMetadataUnpacker struct {
	MetadataType string          `json:"metadataType"`
	Metadata     json.RawMessage `json:"metadata"`
}

func NewArtifact(p *pkg.Package) (Artifact, error) {

	return Artifact{
		artifactBasicMetadata: artifactBasicMetadata{
			Name:      p.Name,
			Version:   p.Version,
			Type:      p.Type,
			FoundBy:   p.FoundBy,
			Locations: p.Locations,
			Licenses:  p.Licenses,
			Language:  p.Language,
		},
		artifactCustomMetadata: artifactCustomMetadata{
			MetadataType: p.MetadataType,
			Metadata:     p.Metadata,
		},
	}, nil
}

func (a Artifact) ToPackage() pkg.Package {
	return pkg.Package{
		// does not include found-by and locations
		Name:         a.Name,
		Version:      a.Version,
		FoundBy:      a.FoundBy,
		Licenses:     a.Licenses,
		Language:     a.Language,
		Locations:    a.Locations,
		Type:         a.Type,
		MetadataType: a.MetadataType,
		Metadata:     a.Metadata,
	}
}

func (a *Artifact) UnmarshalJSON(b []byte) error {
	var basic artifactBasicMetadata
	if err := json.Unmarshal(b, &basic); err != nil {
		return err
	}
	a.artifactBasicMetadata = basic

	var unpacker artifactMetadataUnpacker
	if err := json.Unmarshal(b, &unpacker); err != nil {
		return err
	}

	a.MetadataType = pkg.MetadataType(unpacker.MetadataType)

	switch a.MetadataType {
	case pkg.RpmdbMetadataType:
		var payload pkg.RpmdbMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		a.Metadata = payload
	case pkg.PythonPackageMetadataType:
		var payload pkg.PythonPackageMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		a.Metadata = payload
	case pkg.DpkgMetadataType:
		var payload pkg.DpkgMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		a.Metadata = payload
	case pkg.ApkMetadataType:
		var payload pkg.ApkMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		a.Metadata = payload
	case pkg.JavaMetadataType:
		var payload pkg.JavaMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		a.Metadata = payload
	case pkg.NpmPackageJSONMetadataType:
		var payload pkg.NpmPackageJSONMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		a.Metadata = payload
	case pkg.GemMetadataType:
		var payload pkg.GemMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		a.Metadata = payload
	case "":
		// there may be packages with no metadata, which is OK
	default:
		return fmt.Errorf("unsupported package metadata type: %+v", a.MetadataType)

	}

	return nil
}
