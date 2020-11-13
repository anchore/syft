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

// Presenter writes a CycloneDX report from the given Catalog and Source contents
type Presenter struct {
	catalog *pkg.Catalog
	source  source.Source
	distro  distro.Distro
}

// NewPresenter creates a CycloneDX presenter from the given Catalog and Source objects.
func NewPresenter(catalog *pkg.Catalog, s source.Source, d distro.Distro) *Presenter {
	return &Presenter{
		catalog: catalog,
		source:  s,
		distro:  d,
	}
}

// Present writes the CycloneDX report to the given io.Writer.
func (pres *Presenter) Present(output io.Writer) error {
	bom := NewDocumentFromCatalog(pres.catalog, pres.distro)

	switch src := pres.source.Target.(type) {
	case source.DirSource:
		bom.BomDescriptor.Component = &BdComponent{
			Component: Component{
				Type:    "file",
				Name:    src.Path,
				Version: "",
			},
		}
	case source.ImageSource:
		var imageID string
		var versionStr string
		if len(src.Img.Metadata.Tags) > 0 {
			imageID = src.Img.Metadata.Tags[0].Context().Name()
			versionStr = src.Img.Metadata.Tags[0].TagStr()
		} else {
			imageID = src.Img.Metadata.Digest
		}
		bom.BomDescriptor.Component = &BdComponent{
			Component: Component{
				Type:    "container",
				Name:    imageID,
				Version: versionStr,
			},
		}
	default:
		return fmt.Errorf("unsupported source: %T", src)
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
