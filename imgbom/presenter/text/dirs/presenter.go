package text

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/anchore/imgbom/imgbom/pkg"
)

type Presenter struct {
	catalog *pkg.Catalog
	path    string
}

func NewPresenter(catalog *pkg.Catalog, path string) *Presenter {
	return &Presenter{
		catalog: catalog,
		path:    path,
	}
}

// Present is a method that is in charge of writing to an output buffer
func (pres *Presenter) Present(output io.Writer) error {
	// init the tabular writer
	w := new(tabwriter.Writer)
	w.Init(output, 0, 8, 0, '\t', tabwriter.AlignRight)
	fmt.Fprintln(w, fmt.Sprintf("[Path: %s]", pres.path))

	// populate artifacts...
	// TODO: move this into a common package so that other text presenters can reuse
	for p := range pres.catalog.Enumerate() {
		fmt.Fprintln(w, fmt.Sprintf("[%s]", p.Name))
		fmt.Fprintln(w, " Version:\t", p.Version)
		fmt.Fprintln(w, " Type:\t", p.Type.String())
		if p.Metadata != nil {
			fmt.Fprintf(w, " Metadata:\t%+v\n", p.Metadata)
		}
		fmt.Fprintln(w, " Found by:\t", p.FoundBy)
		fmt.Fprintln(w)
		w.Flush()
	}

	return nil
}
