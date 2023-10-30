package cyclonedxxml

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/internal/log"
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

func (d decoder) Decode(reader io.ReadSeeker) (*sbom.SBOM, sbom.FormatID, string, error) {
	if reader == nil {
		return nil, "", "", fmt.Errorf("no SBOM bytes provided")
	}

	id, version := d.Identify(reader)
	if id != ID {
		return nil, "", "", fmt.Errorf("not a cyclonedx xml document")
	}
	if version == "" {
		return nil, "", "", fmt.Errorf("unsupported cyclonedx xml document version")
	}

	doc, err := d.decoder.Decode(reader)
	if err != nil {
		return nil, id, version, fmt.Errorf("unable to decode cyclonedx xml document: %w", err)
	}

	s, err := cyclonedxhelpers.ToSyftModel(doc)
	if err != nil {
		return nil, id, version, err
	}

	return s, id, version, nil
}

func (d decoder) Identify(reader io.ReadSeeker) (sbom.FormatID, string) {
	if reader == nil {
		return "", ""
	}

	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		log.Debugf("unable to seek to start of CycloneDX XML SBOM: %+v", err)
		return "", ""
	}

	type Document struct {
		XMLNS string `xml:"xmlns,attr"`
	}

	dec := xml.NewDecoder(reader)

	var doc Document
	err := dec.Decode(&doc)
	if err != nil {
		// maybe not xml? maybe not valid? doesn't matter, we won't process it.
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
