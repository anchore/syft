package json

import (
	"encoding/json"
	"fmt"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type Artifact struct {
	ArtifactBasicMetadata
	ArtifactCustomMetadata
}

type ArtifactBasicMetadata struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Type      string    `json:"type"`
	FoundBy   []string  `json:"foundBy"`
	Locations Locations `json:"locations,omitempty"`
	Licenses  []string  `json:"licenses"`
	Language  string    `json:"language"`
}

type ArtifactCustomMetadata struct {
	MetadataType pkg.MetadataType `json:"metadataType"`
	Metadata     interface{}      `json:"metadata,omitempty"`
}

type ArtifactMetadataUnpacker struct {
	MetadataType string          `json:"metadataType"`
	Metadata     json.RawMessage `json:"metadata"`
}

func NewArtifact(p *pkg.Package, s source.Source) (Artifact, error) {
	locations, err := NewLocations(p, s)
	if err != nil {
		return Artifact{}, err
	}

	return Artifact{
		ArtifactBasicMetadata: ArtifactBasicMetadata{
			Name:      p.Name,
			Version:   p.Version,
			Type:      string(p.Type),
			FoundBy:   []string{p.FoundBy},
			Locations: locations,
			Licenses:  p.Licenses,
			Language:  string(p.Language),
		},
		ArtifactCustomMetadata: ArtifactCustomMetadata{
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
		Licenses:     a.Licenses,
		Language:     pkg.Language(a.Language),
		Type:         pkg.Type(a.Type),
		MetadataType: a.MetadataType,
		Metadata:     a.Metadata,
	}
}

func (a *Artifact) UnmarshalJSON(b []byte) error {
	var basic ArtifactBasicMetadata
	if err := json.Unmarshal(b, &basic); err != nil {
		return err
	}
	a.ArtifactBasicMetadata = basic

	var unpacker ArtifactMetadataUnpacker
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
