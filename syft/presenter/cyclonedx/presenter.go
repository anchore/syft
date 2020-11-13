/*
Package cyclonedx is responsible for generating a CycloneDX XML report for the given container image or file system.
*/
package cyclonedx

import (
	"encoding/xml"
	"fmt"
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
func NewPresenter(catalog *pkg.Catalog, s source.Metadata, d distro.Distro) *Presenter {
	return &Presenter{
		catalog:     catalog,
		srcMetadata: s,
		distro:      d,
	}
}

// Present writes the CycloneDX report to the given io.Writer.
func (pres *Presenter) Present(output io.Writer) error {
	bom := NewDocumentFromCatalog(pres.catalog, pres.distro)

	switch pres.srcMetadata.Scheme {
	case source.DirectoryScheme:
		bom.BomDescriptor.Component = &BdComponent{
			Component: Component{
				Type:    "file",
				Name:    pres.srcMetadata.Path,
				Version: "",
			},
		}
	case source.ImageScheme:
		// TODO: can we use the tags a bit better?
		bom.BomDescriptor.Component = &BdComponent{
			Component: Component{
				Type:    "container",
				Name:    pres.srcMetadata.ImageMetadata.UserInput,
				Version: pres.srcMetadata.ImageMetadata.Digest,
			},
		}
	default:
		return fmt.Errorf("unsupported source: %T", pres.srcMetadata.Scheme)
	}

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
