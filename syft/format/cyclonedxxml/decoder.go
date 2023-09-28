package cyclonedxxml

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/format/internal/cyclonedxutil"
	"github.com/anchore/syft/syft/sbom"
)

var _ sbom.FormatDecoder = (*decoder)(nil)

type decoder struct {
	decoder cyclonedxutil.Decoder
}

func NewFormatDecoder() sbom.FormatDecoder {
	return decoder{
		decoder: cyclonedxutil.NewDecoder(cyclonedx.BOMFileFormatXML),
	}
}

func (d decoder) Decode(by []byte) (*sbom.SBOM, sbom.FormatID, string, error) {
	id, version := d.Identify(by)
	if id != ID {
		return nil, "", "", fmt.Errorf("not a cyclonedx json document")
	}
	if version == "" {
		return nil, "", "", fmt.Errorf("unsupported cyclonedx json document version")
	}

	doc, err := d.decoder.Decode(by)
	if err != nil {
		return nil, id, version, fmt.Errorf("unable to decode cyclonedx json document: %w", err)
	}

	s, err := cyclonedxhelpers.ToSyftModel(doc)
	if err != nil {
		return nil, id, version, err
	}

	return s, id, version, nil
}

func (d decoder) Identify(by []byte) (sbom.FormatID, string) {
	type Document struct {
		XMLNS string `xml:"xmlns,attr"`
	}

	var doc Document
	err := xml.Unmarshal(by, &doc)
	if err != nil {
		// maybe not json? maybe not valid? doesn't matter, we won't process it.
		return "", ""
	}

	id, version := getFormatInfo(doc.XMLNS)
	if version == "" || id != ID {
		// not a cyclonedx xml document that we support
		return "", ""
	}

	return id, version
}

func getFormatInfo(xmlns string) (sbom.FormatID, string) {
	version := getVersionFromXMLNS(xmlns)

	if !strings.Contains(xmlns, "cyclonedx.org/schema/bom") {
		// not a cyclonedx xml document
		return "", ""
	}

	spec, err := cyclonedxutil.SpecVersionFromString(version)
	if spec < 0 || err != nil {
		// not a supported version, but is cyclonedx xml
		return ID, ""
	}
	return ID, version
}

func getVersionFromXMLNS(xmlns string) string {
	fields := strings.Split(xmlns, "/")
	return fields[len(fields)-1]
}
