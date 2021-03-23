/*
Package cyclonedx is responsible for generating a CycloneDX XML report for the given container image or file system.
*/
package packages

import (
	"encoding/xml"
	"io"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// CycloneDxPresenter writes a CycloneDX report from the given Catalog and Locations contents
type CycloneDxPresenter struct {
	catalog     *pkg.Catalog
	srcMetadata source.Metadata
}

// NewCycloneDxPresenter creates a CycloneDX presenter from the given Catalog and Locations objects.
func NewCycloneDxPresenter(catalog *pkg.Catalog, srcMetadata source.Metadata) *CycloneDxPresenter {
	return &CycloneDxPresenter{
		catalog:     catalog,
		srcMetadata: srcMetadata,
	}
}

// Present writes the CycloneDX report to the given io.Writer.
func (pres *CycloneDxPresenter) Present(output io.Writer) error {
	bom := NewCycloneDxDocument(pres.catalog, pres.srcMetadata)

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
