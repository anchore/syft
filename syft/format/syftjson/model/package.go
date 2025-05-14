package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/packagemetadata"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
)

var errUnknownMetadataType = errors.New("unknown metadata type")

// Package represents a pkg.Package object specialized for JSON marshaling and unmarshalling.
type Package struct {
	PackageBasicData
	PackageCustomData
}

// PackageBasicData contains non-ambiguous values (type-wise) from pkg.Package.
type PackageBasicData struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	Type      pkg.Type        `json:"type"`
	FoundBy   string          `json:"foundBy"`
	Locations []file.Location `json:"locations"`
	Licenses  licenses        `json:"licenses"`
	Language  pkg.Language    `json:"language"`
	CPEs      cpes            `json:"cpes"`
	PURL      string          `json:"purl"`
}

type cpes []CPE

type CPE struct {
	Value  string `json:"cpe"`
	Source string `json:"source,omitempty"`
}

type licenses []License

type License struct {
	Value          string          `json:"value"`
	SPDXExpression string          `json:"spdxExpression"`
	Type           license.Type    `json:"type"`
	URLs           []string        `json:"urls"`
	Locations      []file.Location `json:"locations"`
	Contents       string          `json:"contents,omitempty"`
}

func newModelLicensesFromValues(licenses []string) (ml []License) {
	for _, v := range licenses {
		expression, err := license.ParseExpression(v)
		if err != nil {
			log.Tracef("could not find valid spdx expression for %s: %w", v, err)
		}
		ml = append(ml, License{
			Value:          v,
			SPDXExpression: expression,
			Type:           license.Declared,
		})
	}
	return ml
}

func (f *licenses) UnmarshalJSON(b []byte) error {
	var lics []License
	if err := json.Unmarshal(b, &lics); err != nil {
		var simpleLicense []string
		if err := json.Unmarshal(b, &simpleLicense); err != nil {
			return fmt.Errorf("unable to unmarshal license: %w", err)
		}
		lics = newModelLicensesFromValues(simpleLicense)
	}
	*f = lics
	return nil
}

func sourcedCPESfromSimpleCPEs(simpleCPEs []string) []CPE {
	var result []CPE
	for _, s := range simpleCPEs {
		result = append(result, CPE{
			Value: s,
		})
	}
	return result
}

func (c *cpes) UnmarshalJSON(b []byte) error {
	var cs []CPE
	if err := json.Unmarshal(b, &cs); err != nil {
		var simpleCPEs []string
		if err := json.Unmarshal(b, &simpleCPEs); err != nil {
			return fmt.Errorf("unable to unmarshal cpes: %w", err)
		}
		cs = sourcedCPESfromSimpleCPEs(simpleCPEs)
	}
	*c = cs
	return nil
}

// PackageCustomData contains ambiguous values (type-wise) from pkg.Package.
type PackageCustomData struct {
	MetadataType string `json:"metadataType,omitempty"`
	Metadata     any    `json:"metadata,omitempty"`
}

// packageMetadataUnpacker is all values needed from Package to disambiguate ambiguous fields during json unmarshaling.
type packageMetadataUnpacker struct {
	MetadataType string          `json:"metadataType"`
	Metadata     json.RawMessage `json:"metadata"`
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

	err := unpackPkgMetadata(p, unpacker)
	if errors.Is(err, errUnknownMetadataType) {
		log.Warnf("unknown package metadata type=%q for packageID=%q", p.MetadataType, p.ID)
		return nil
	}

	return err
}

func unpackPkgMetadata(p *Package, unpacker packageMetadataUnpacker) error {
	if unpacker.MetadataType == "" {
		return nil
	}

	// check for legacy correction cases from schema v11 -> v12
	ty := unpacker.MetadataType
	switch unpacker.MetadataType {
	case "HackageMetadataType":
		for _, l := range p.Locations {
			if strings.HasSuffix(l.RealPath, ".yaml.lock") {
				ty = "haskell-hackage-stack-lock-entry"
				break
			} else if strings.HasSuffix(l.RealPath, ".yaml") {
				ty = "haskell-hackage-stack-entry"
				break
			}
		}
	case "RpmMetadata":
		for _, l := range p.Locations {
			if strings.HasSuffix(l.RealPath, ".rpm") {
				ty = "rpm-archive"
				break
			}
		}
	case "RustCargoPackageMetadata":
		var found bool
		for _, l := range p.Locations {
			if strings.HasSuffix(strings.ToLower(l.RealPath), "cargo.lock") {
				ty = "rust-cargo-lock-entry"
				found = true
				break
			}
		}
		if !found {
			ty = "rust-cargo-audit-entry"
		}
	}

	typ := packagemetadata.ReflectTypeFromJSONName(ty)
	if typ == nil {
		// capture unknown metadata as a generic struct
		if len(unpacker.Metadata) > 0 {
			var val interface{}
			if err := json.Unmarshal(unpacker.Metadata, &val); err != nil {
				return err
			}
			p.Metadata = val
		}

		return errUnknownMetadataType
	}

	val := reflect.New(typ).Interface()
	if len(unpacker.Metadata) > 0 {
		if err := json.Unmarshal(unpacker.Metadata, val); err != nil {
			return err
		}
	}
	p.Metadata = reflect.ValueOf(val).Elem().Interface()
	return nil
}
