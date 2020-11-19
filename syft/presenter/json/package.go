package json

import (
	"encoding/json"
	"fmt"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// Package represents a pkg.Package object specialized for JSON marshaling and unmarshaling.
type Package struct {
	packageBasicMetadata
	packageCustomMetadata
}

// packageBasicMetadata contains non-ambiguous values (type-wise) from pkg.Package.
type packageBasicMetadata struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Type      pkg.Type          `json:"type"`
	FoundBy   string            `json:"foundBy"`
	Locations []source.Location `json:"locations"`
	Licenses  []string          `json:"licenses"`
	Language  pkg.Language      `json:"language"`
	CPEs      []string          `json:"cpes"`
	PURL      string            `json:"purl"`
}

// packageCustomMetadata contains ambiguous values (type-wise) from pkg.Package.
type packageCustomMetadata struct {
	MetadataType pkg.MetadataType `json:"metadataType"`
	Metadata     interface{}      `json:"metadata,omitempty"`
}

// packageMetadataUnpacker is all values needed from Package to disambiguate ambiguous fields during json unmarshaling.
type packageMetadataUnpacker struct {
	MetadataType string          `json:"metadataType"`
	Metadata     json.RawMessage `json:"metadata"`
}

// NewPackage crates a new Package from the given pkg.Package.
func NewPackage(p *pkg.Package) (Package, error) {
	var cpes = make([]string, len(p.CPEs))
	for i, c := range p.CPEs {
		cpes[i] = c.BindToFmtString()
	}
	return Package{
		packageBasicMetadata: packageBasicMetadata{
			Name:      p.Name,
			Version:   p.Version,
			Type:      p.Type,
			FoundBy:   p.FoundBy,
			Locations: p.Locations,
			Licenses:  p.Licenses,
			Language:  p.Language,
			CPEs:      cpes,
			PURL:      p.PURL,
		},
		packageCustomMetadata: packageCustomMetadata{
			MetadataType: p.MetadataType,
			Metadata:     p.Metadata,
		},
	}, nil
}

// ToPackage generates a pkg.Package from the current Package.
func (a Package) ToPackage() (pkg.Package, error) {
	var cpes = make([]pkg.CPE, len(a.CPEs))
	var err error
	for i, c := range a.CPEs {
		cpes[i], err = pkg.NewCPE(c)
		if err != nil {
			return pkg.Package{}, fmt.Errorf("unable to parse CPE from JSON package: %w", err)
		}
	}
	return pkg.Package{
		// does not include found-by and locations
		Name:         a.Name,
		Version:      a.Version,
		FoundBy:      a.FoundBy,
		Licenses:     a.Licenses,
		Language:     a.Language,
		Locations:    a.Locations,
		CPEs:         cpes,
		PURL:         a.PURL,
		Type:         a.Type,
		MetadataType: a.MetadataType,
		Metadata:     a.Metadata,
	}, nil
}

// UnmarshalJSON is a custom unmarshaller for handling basic values and values with ambiguous types.
// nolint:funlen
func (a *Package) UnmarshalJSON(b []byte) error {
	var basic packageBasicMetadata
	if err := json.Unmarshal(b, &basic); err != nil {
		return err
	}
	a.packageBasicMetadata = basic

	var unpacker packageMetadataUnpacker
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
