package packages

import (
	"fmt"

	"io"
	"text/tabwriter"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// TextPresenter is a human-friendly text presenter to represent package and source data.
type TextPresenter struct {
	catalog     *pkg.Catalog
	srcMetadata source.Metadata
}

// NewTextPresenter creates a new presenter for the given set of catalog and image data.
func NewTextPresenter(catalog *pkg.Catalog, srcMetadata source.Metadata) *TextPresenter {
	return &TextPresenter{
		catalog:     catalog,
		srcMetadata: srcMetadata,
	}
}

// Present is a method that is in charge of writing to an output buffer
func (pres *TextPresenter) Present(output io.Writer) error {
	// init the tabular writer
	w := new(tabwriter.Writer)
	w.Init(output, 0, 8, 0, '\t', tabwriter.AlignRight)

	switch pres.srcMetadata.Scheme {
	case source.DirectoryScheme:
		fmt.Fprintln(w, fmt.Sprintf("[Path: %s]", pres.srcMetadata.Path))
	case source.ImageScheme:
		fmt.Fprintln(w, "[Image]")

		for idx, l := range pres.srcMetadata.ImageMetadata.Layers {
			fmt.Fprintln(w, " Layer:\t", idx)
			fmt.Fprintln(w, " Digest:\t", l.Digest)
			fmt.Fprintln(w, " Size:\t", l.Size)
			fmt.Fprintln(w, " MediaType:\t", l.MediaType)
			fmt.Fprintln(w)
			w.Flush()
		}
	default:
		return fmt.Errorf("unsupported source: %T", pres.srcMetadata.Scheme)
	}

	// populate artifacts...
	rows := 0
	for _, p := range pres.catalog.Sorted() {
		fmt.Fprintln(w, fmt.Sprintf("[%s]", p.Name))
		fmt.Fprintln(w, " Version:\t", p.Version)
		fmt.Fprintln(w, " Type:\t", string(p.Type))
		fmt.Fprintln(w, " Found by:\t", p.FoundBy)
		fmt.Fprintln(w)
		w.Flush()
		rows++
	}

	if rows == 0 {
		fmt.Fprintln(output, "No packages discovered")
		return nil
	}

	return nil
}
