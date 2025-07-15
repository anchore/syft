package purls

import (
	"io"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "purls"
const version = "1"

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
		"purl",
	}
}

func (e encoder) Version() string {
	return sbom.AnyVersion
}

func (e encoder) Encode(writer io.Writer, s sbom.SBOM) error {
	output := strset.New()
	for _, p := range s.Artifacts.Packages.Sorted() {
		purl := strings.TrimSpace(p.PURL)
		if purl == "" || output.Has(purl) {
			continue
		}
		// ensure syft doesn't output invalid PURLs in this format
		_, err := packageurl.FromString(purl)
		if err != nil {
			log.Debugf("invalid purl: %q", purl)
			continue
		}
		output.Add(purl)
		_, err = writer.Write([]byte(purl))
		if err != nil {
			return err
		}
		_, err = writer.Write([]byte("\n"))
		if err != nil {
			return err
		}
	}
	return nil
}
