package cyclonedx12xml

import (
	"encoding/xml"
	"io"

	"github.com/anchore/syft/syft/distro"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func encoder(output io.Writer, catalog *pkg.Catalog, srcMetadata *source.Metadata, d *distro.Distro, scope source.Scope) error {
	enc := xml.NewEncoder(output)
	enc.Indent("", "  ")

	_, err := output.Write([]byte(xml.Header))
	if err != nil {
		return err
	}

	err = enc.Encode(toFormatModel(catalog, srcMetadata, d, scope))
	if err != nil {
		return err
	}

	_, err = output.Write([]byte("\n"))
	return err
}
