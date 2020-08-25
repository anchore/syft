/*
Package cyclonedx is responsible for generating a CycloneDX XML report for the given container image or file system.
*/
package cyclonedx

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

// Presenter writes a CycloneDX report from the given Catalog and Scope contents
type Presenter struct {
	catalog *pkg.Catalog
	scope   scope.Scope
}

// NewPresenter creates a CycloneDX presenter from the given Catalog and Scope objects.
func NewPresenter(catalog *pkg.Catalog, s scope.Scope) *Presenter {
	return &Presenter{
		catalog: catalog,
		scope:   s,
	}
}

// Present writes the CycloneDX report to the given io.Writer.
func (pres *Presenter) Present(output io.Writer) error {
	bom := NewDocumentFromCatalog(pres.catalog)

	srcObj := pres.scope.Source()

	switch src := srcObj.(type) {
	case scope.DirSource:
		bom.BomDescriptor.Component = &BdComponent{
			Component: Component{
				Type:    "file",
				Name:    src.Path,
				Version: "",
			},
		}
	case scope.ImageSource:
		var imageID string
		var versionStr string
		if len(src.Img.Metadata.Tags) > 0 {
			imageID = src.Img.Metadata.Tags[0].Context().Name()
			versionStr = src.Img.Metadata.Tags[0].TagStr()
		} else {
			imageID = src.Img.Metadata.Digest
		}
		src.Img.Metadata.Tags[0].TagStr()
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

	xmlOut, err := xml.MarshalIndent(bom, " ", "  ")
	if err != nil {
		return err
	}

	_, err = output.Write([]byte(xml.Header))
	if err != nil {
		return err
	}
	_, err = output.Write(xmlOut)
	if err != nil {
		return err
	}

	_, err = output.Write([]byte("\n"))
	return err
}
