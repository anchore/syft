package cyclonedxutil

import (
	"io"
	"slices"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/scylladb/go-set/strset"

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
	if e.version < cyclonedx.SpecVersion1_5 {
		// evidence occurrences are a 1.5+ field; cyclonedx-go strips the occurrences for older spec versions but
		// leaves the emptied evidence element behind, so drop it rather than emit an empty element
		dropEvidence(bom.Components)
	}
	if e.version >= cyclonedx.SpecVersion1_7 {
		// evidence occurrences are the standard home for package locations and state everything the syft:location
		// properties do, so the properties are not written as well
		dropProperties(bom.Components, locationPropertyPrefix)
	} else {
		// older spec versions keep the syft:location properties so that documents pinned to those versions stay
		// backwards compatible; the layer and the path within an archive are stated there, and the additional context
		// of an occurrence only exists from spec 1.6, so the occurrences are one per distinct path
		dropOccurrenceContext(bom.Components)
	}
	enc := cyclonedx.NewBOMEncoder(writer, e.format)
	enc.SetPretty(e.pretty)
	enc.SetEscapeHTML(false)

	return enc.EncodeVersion(bom, e.version)
}

// locationPropertyPrefix is the prefix of the names of the properties that describe the locations of a package
const locationPropertyPrefix = "syft:location:"

func dropProperties(components *[]cyclonedx.Component, prefix string) {
	if components == nil {
		return
	}
	for i := range *components {
		c := &(*components)[i]
		dropProperties(c.Components, prefix)
		if c.Properties == nil {
			continue
		}
		properties := slices.DeleteFunc(*c.Properties, func(p cyclonedx.Property) bool {
			return strings.HasPrefix(p.Name, prefix)
		})
		if len(properties) == 0 {
			c.Properties = nil
			continue
		}
		c.Properties = &properties
	}
}

func dropOccurrenceContext(components *[]cyclonedx.Component) {
	if components == nil {
		return
	}
	for i := range *components {
		c := &(*components)[i]
		dropOccurrenceContext(c.Components)
		if c.Evidence == nil || c.Evidence.Occurrences == nil {
			continue
		}
		var occurrences []cyclonedx.EvidenceOccurrence
		paths := strset.New()
		for _, o := range *c.Evidence.Occurrences {
			if paths.Has(o.Location) {
				continue
			}
			paths.Add(o.Location)
			o.AdditionalContext = ""
			occurrences = append(occurrences, o)
		}
		c.Evidence.Occurrences = &occurrences
	}
}

func dropEvidence(components *[]cyclonedx.Component) {
	if components == nil {
		return
	}
	for i := range *components {
		c := &(*components)[i]
		dropEvidence(c.Components)
		c.Evidence = nil
	}
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
