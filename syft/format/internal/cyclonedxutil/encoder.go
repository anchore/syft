package cyclonedxutil

import (
	"io"
	"slices"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

type Encoder struct {
	version cyclonedx.SpecVersion
	format  cyclonedx.BOMFileFormat
	pretty  bool
}

func NewEncoder(version string, format cyclonedx.BOMFileFormat, pretty bool) (Encoder, error) {
	specVersion, err := SpecVersionFromString(version)
	if err != nil {
		return Encoder{}, err
	}
	return Encoder{
		version: specVersion,
		format:  format,
		pretty:  pretty,
	}, nil
}

func (e Encoder) Encode(writer io.Writer, s sbom.SBOM) error {
	bom := cyclonedxhelpers.ToFormatModel(s)
	if e.version < cyclonedx.SpecVersion1_6 {
		// cyclonedx-go does not downgrade this 1.6+ reference type for older spec versions
		// (see https://github.com/CycloneDX/cyclonedx-go/issues/291), so drop it rather than emit an invalid document
		dropExternalReferenceType(bom.Components, cyclonedx.ERTypeSourceDistribution)
	}
	enc := cyclonedx.NewBOMEncoder(writer, e.format)
	enc.SetPretty(e.pretty)
	enc.SetEscapeHTML(false)

	return enc.EncodeVersion(bom, e.version)
}

func dropExternalReferenceType(components *[]cyclonedx.Component, refType cyclonedx.ExternalReferenceType) {
	if components == nil {
		return
	}
	for i := range *components {
		c := &(*components)[i]
		dropExternalReferenceType(c.Components, refType)
		if c.ExternalReferences == nil {
			continue
		}
		refs := slices.DeleteFunc(*c.ExternalReferences, func(r cyclonedx.ExternalReference) bool {
			return r.Type == refType
		})
		if len(refs) == 0 {
			c.ExternalReferences = nil
			continue
		}
		c.ExternalReferences = &refs
	}
}
