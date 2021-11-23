package cyclonedx12xml

import (
	"encoding/xml"
	"io"

	"github.com/anchore/syft/syft/sbom"
)

func encoder(output io.Writer, s sbom.SBOM) error {
	enc := xml.NewEncoder(output)
	enc.Indent("", "  ")

	_, err := output.Write([]byte(xml.Header))
	if err != nil {
		return err
	}

	err = enc.Encode(toFormatModel(s))
	if err != nil {
		return err
	}

	_, err = output.Write([]byte("\n"))
	return err
}
