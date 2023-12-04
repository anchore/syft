package options

import (
	"bytes"
	"fmt"

	"github.com/anchore/syft/syft/sbom"
)

type SbomBuffer struct {
	Format sbom.FormatEncoder
	buf    *bytes.Buffer
}

func (w *SbomBuffer) Read() []byte {
	if w.buf != nil {
		return w.buf.Bytes()
	}

	return []byte{}
}

func (w *SbomBuffer) Write(s sbom.SBOM) error {
	if w.buf == nil {
		w.buf = &bytes.Buffer{}
	}
	if err := w.Format.Encode(w.buf, s); err != nil {
		return fmt.Errorf("unable to encode SBOM: %w", err)
	}
	return nil
}
