package purls

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/format/internal"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

var _ sbom.FormatDecoder = (*decoder)(nil)

type decoder struct{}

func NewFormatDecoder() sbom.FormatDecoder {
	return decoder{}
}

func (d decoder) Decode(r io.Reader) (*sbom.SBOM, sbom.FormatID, string, error) {
	if r == nil {
		return nil, "", "", fmt.Errorf("no reader provided")
	}
	s, err := toSyftModel(r)
	return s, ID, version, err
}

func (d decoder) Identify(r io.Reader) (sbom.FormatID, string) {
	if r == nil {
		return "", ""
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			// skip whitespace only lines
			continue
		}
		if strings.HasPrefix(line, "pkg:") {
			_, err := packageurl.FromString(line)
			if err != nil {
				log.WithFields("error", err, "line", line).Debug("unable to parse purl")
				continue
			}
			return ID, version
		}
		// not a purl, so we can't identify the format as a list of purls
		return "", ""
	}

	return "", ""
}

func toSyftModel(r io.Reader) (*sbom.SBOM, error) {
	var errs []error
	pkgs := pkg.NewCollection()

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		// skip invalid PURLs
		_, err := packageurl.FromString(line)
		if err != nil {
			log.WithFields("error", err, "line", line).Debug("unable to parse purl")
			continue
		}
		p := pkg.Package{
			// name, version and other properties set during Backfill
			PURL: line,
		}

		internal.Backfill(&p)
		p.SetID()
		pkgs.Add(p)
	}

	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkgs,
		},
	}, errors.Join(errs...)
}
