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
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Type      string            `json:"type"`
	FoundBy   string            `json:"foundBy"`
	Locations []source.Location `json:"locations"`
	Licenses  []string          `json:"licenses"`
	Language  string            `json:"language"`
	CPEs      []string          `json:"cpes"`
	PURL      string            `json:"purl"`
}

// packageCustomMetadata contains ambiguous values (type-wise) from pkg.Package.
type packageCustomMetadata struct {
	MetadataType string      `json:"metadataType"`
	Metadata     interface{} `json:"metadata"`
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

	// ensure collections are never nil for presentation reasons

	var locations = make([]source.Location, 0)
	if p.Locations != nil {
		locations = p.Locations
	}

	var licenses = make([]string, 0)
	if p.Licenses != nil {
		licenses = p.Licenses
	}

	return Package{
		packageBasicMetadata: packageBasicMetadata{
			ID:        string(p.ID),
			Name:      p.Name,
			Version:   p.Version,
			Type:      string(p.Type),
			FoundBy:   p.FoundBy,
			Locations: locations,
			Licenses:  licenses,
			Language:  string(p.Language),
			CPEs:      cpes,
			PURL:      p.PURL,
		},
		packageCustomMetadata: packageCustomMetadata{
			MetadataType: string(p.MetadataType),
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
		ID:           pkg.ID(a.ID),
		Name:         a.Name,
		Version:      a.Version,
		FoundBy:      a.FoundBy,
		Licenses:     a.Licenses,
		Language:     pkg.Language(a.Language),
		Locations:    a.Locations,
		CPEs:         cpes,
		PURL:         a.PURL,
		Type:         pkg.Type(a.Type),
		MetadataType: pkg.MetadataType(a.MetadataType),
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

	a.MetadataType = unpacker.MetadataType

	switch pkg.MetadataType(a.MetadataType) {
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
	case pkg.RustCrateMetadataType:
		var payload pkg.CargoPackageMetadata
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
