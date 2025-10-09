package cpes

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/format/internal"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "cpes"
const version = "1"

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

		err := cpe.ValidateString(line)
		if err != nil {
			return "", ""
		}

		return ID, version
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

		// skip invalid CPEs
		c, err := cpe.New(line, "")
		if err != nil {
			log.WithFields("error", err, "line", line).Debug("unable to parse cpe")
			continue
		}

		p := pkg.Package{
			Name:    c.Attributes.Product,
			Version: c.Attributes.Version,
			CPEs:    []cpe.CPE{c},
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
