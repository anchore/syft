package text

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/anchore/imgbom/imgbom/pkg"
	stereoscopeImg "github.com/anchore/stereoscope/pkg/image"
)

// Presenter holds the Present method to produce output
type Presenter struct{}

// NewPresenter is a constructor for a Presenter
func NewPresenter() *Presenter {
	return &Presenter{}
}

// Present is a method that is in charge of writing to an output buffer
func (pres *Presenter) Present(output io.Writer, img *stereoscopeImg.Image, catalog *pkg.Catalog) error {
	tags := make([]string, len(img.Metadata.Tags))
	for idx, tag := range img.Metadata.Tags {
		tags[idx] = tag.String()
	}

	// init the tabular writer
	w := new(tabwriter.Writer)
	w.Init(output, 0, 8, 0, '\t', tabwriter.AlignRight)

	fmt.Fprintln(w, "[Image]")

	for idx, l := range img.Layers {
		fmt.Fprintln(w, " Layer:\t", idx)
		fmt.Fprintln(w, " Digest:\t", l.Metadata.Digest)
		fmt.Fprintln(w, " Size:\t", l.Metadata.Size)
		fmt.Fprintln(w, " MediaType:\t", l.Metadata.MediaType)
		fmt.Fprintln(w)
		w.Flush()
	}

	// populate artifacts...
	for p := range catalog.Enumerate() {
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
