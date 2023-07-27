package text

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func encoder(output io.Writer, s sbom.SBOM) error {
	// init the tabular writer
	w := new(tabwriter.Writer)
	w.Init(output, 0, 8, 0, '\t', tabwriter.AlignRight)

	switch metadata := s.Source.Metadata.(type) {
	case source.DirectorySourceMetadata:
		fmt.Fprintf(w, "[Path: %s]\n", metadata.Path)
	case source.FileSourceMetadata:
		fmt.Fprintf(w, "[Path: %s]\n", metadata.Path)
	case source.StereoscopeImageSourceMetadata:
		fmt.Fprintln(w, "[Image]")

		for idx, l := range metadata.Layers {
			fmt.Fprintln(w, " Layer:\t", idx)
			fmt.Fprintln(w, " Digest:\t", l.Digest)
			fmt.Fprintln(w, " Size:\t", l.Size)
			fmt.Fprintln(w, " MediaType:\t", l.MediaType)
			fmt.Fprintln(w)
			w.Flush()
		}
	default:
		return fmt.Errorf("unsupported source: %T", s.Source.Metadata)
	}

	// populate artifacts...
	rows := 0
	for _, p := range s.Artifacts.Packages.Sorted() {
		fmt.Fprintf(w, "[%s]\n", p.Name)
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
