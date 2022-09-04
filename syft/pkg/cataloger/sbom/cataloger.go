package sbom

import (
	"bytes"
	"fmt"
	"io"

	"github.com/anchore/syft/internal/formats/cyclonedxjson"
	"github.com/anchore/syft/internal/formats/cyclonedxxml"
	"github.com/anchore/syft/internal/formats/spdx22json"
	"github.com/anchore/syft/internal/formats/spdx22tagvalue"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"github.com/anchore/syft/syft/sbom"
)

// NewSBOMCataloger returns a new SBOM cataloger object loaded from saved SBOM JSON.
func NewSBOMCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/*.syft.json": makeParser(syftjson.Format()),
		"**/bom.json":    makeParser(cyclonedxjson.Format()),
		"**/bom.xml":     makeParser(cyclonedxxml.Format()),
		"**/*.cdx.json":  makeParser(cyclonedxjson.Format()),
		"**/*.cdx.xml":   makeParser(cyclonedxxml.Format()),
		"**/*.spdx.json": makeParser(spdx22json.Format()),
		"**/*.spdx":      makeParser(spdx22tagvalue.Format()),
	}
	return common.NewGenericCataloger(nil, globParsers, "sbom-cataloger")
}

func makeParser(format sbom.Format) func(string, io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	return func(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
		by, err := io.ReadAll(reader)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read sbom: %w", err)
		}

		s, err := format.Decode(bytes.NewReader(by))
		if err != nil {
			return nil, nil, fmt.Errorf("unable to decode sbom: %w", err)
		}

		var packages []*pkg.Package
		for _, p := range s.Artifacts.PackageCatalog.Sorted() {
			x := p // copy
			packages = append(packages, &x)
		}

		return packages, nil, nil
	}
}
