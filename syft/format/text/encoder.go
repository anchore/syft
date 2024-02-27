package text

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const ID sbom.FormatID = "syft-text"

type encoder struct {
}

func NewFormatEncoder() sbom.FormatEncoder {
	return encoder{}
}

func (e encoder) ID() sbom.FormatID {
	return ID
}

func (e encoder) Aliases() []string {
	return []string{
		"text",
	}
}

func (e encoder) Version() string {
	return sbom.AnyVersion
}

func (e encoder) Encode(writer io.Writer, s sbom.SBOM) error {
	// init the tabular writer
	w := new(tabwriter.Writer)
	w.Init(writer, 0, 8, 0, '\t', tabwriter.AlignRight)

	switch metadata := s.Source.Metadata.(type) {
	case source.DirectoryMetadata:
		fmt.Fprintf(w, "[Path: %s]\n", metadata.Path)
	case source.FileMetadata:
		fmt.Fprintf(w, "[Path: %s]\n", metadata.Path)
	case source.ImageMetadata:
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
		fmt.Fprintln(writer, "No packages discovered")
		return nil
	}

	return nil
}
