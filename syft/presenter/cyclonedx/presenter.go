/*
Package cyclonedx is responsible for generating a CycloneDX XML report for the given container image or file system.
*/
package cyclonedx

import (
	"encoding/xml"
	"io"

	"github.com/anchore/syft/syft/distro"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// Presenter writes a CycloneDX report from the given Catalog and Locations contents
type Presenter struct {
	catalog     *pkg.Catalog
	srcMetadata source.Metadata
	distro      distro.Distro
}

// NewPresenter creates a CycloneDX presenter from the given Catalog and Locations objects.
func NewPresenter(catalog *pkg.Catalog, srcMetadata source.Metadata, d distro.Distro) *Presenter {
	return &Presenter{
		catalog:     catalog,
		srcMetadata: srcMetadata,
		distro:      d,
	}
}

// Present writes the CycloneDX report to the given io.Writer.
func (pres *Presenter) Present(output io.Writer) error {
	bom := NewDocument(pres.catalog, pres.distro, pres.srcMetadata)

	encoder := xml.NewEncoder(output)
	encoder.Indent("", "  ")

	_, err := output.Write([]byte(xml.Header))
	if err != nil {
		return err
	}

	err = encoder.Encode(bom)
	if err != nil {
		return err
	}

	_, err = output.Write([]byte("\n"))
	return err
}
