package text

import (
	"fmt"

	"io"
	"text/tabwriter"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

type Presenter struct {
	catalog *pkg.Catalog
	scope   scope.Scope
}

func NewPresenter(catalog *pkg.Catalog, s scope.Scope) *Presenter {
	return &Presenter{
		catalog: catalog,
		scope:   s,
	}
}

// Present is a method that is in charge of writing to an output buffer
func (pres *Presenter) Present(output io.Writer) error {
	// init the tabular writer
	w := new(tabwriter.Writer)
	w.Init(output, 0, 8, 0, '\t', tabwriter.AlignRight)

	switch src := pres.scope.Source.(type) {
	case scope.DirSource:
		fmt.Fprintln(w, fmt.Sprintf("[Path: %s]", src.Path))
	case scope.ImageSource:
		fmt.Fprintln(w, "[Image]")

		for idx, l := range src.Img.Layers {
			fmt.Fprintln(w, " Layer:\t", idx)
			fmt.Fprintln(w, " Digest:\t", l.Metadata.Digest)
			fmt.Fprintln(w, " Size:\t", l.Metadata.Size)
			fmt.Fprintln(w, " MediaType:\t", l.Metadata.MediaType)
			fmt.Fprintln(w)
			w.Flush()
		}
	default:
		return fmt.Errorf("unsupported source: %T", src)
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
