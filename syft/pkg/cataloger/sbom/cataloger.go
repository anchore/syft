package sbom

import (
	"bytes"
	"fmt"
	"github.com/anchore/syft/internal/formats/cyclonedxjson"
	"github.com/anchore/syft/internal/formats/cyclonedxxml"
	"github.com/anchore/syft/internal/formats/spdx22json"
	"github.com/anchore/syft/internal/formats/spdx22tagvalue"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"github.com/anchore/syft/syft/sbom"
	"io"
)

// NewSBOMCataloger returns a new SBOM cataloger object loaded from saved SBOM JSON.
func NewSBOMCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/*.syft.json": parseSyftJSON,
		"**/bom.json":    parseCyclonedxJSON,
		"**/bom.xml":     parseCyclonedxXML,
		"**/*.cdx.json":  parseCyclonedxJSON,
		"**/*.cdx.xml":   parseCyclonedxXML,
		"**/*.spdx.json": parseSpdxJSON,
		"**/*.spdx":      parseSpdx,
	}
	return common.NewGenericCataloger(nil, globParsers, "sbom-cataloger")
}

func parseSyftJSON(path string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	return parseSBOM(path, reader, syftjson.Format())
}

func parseCyclonedxJSON(path string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	return parseSBOM(path, reader, cyclonedxjson.Format())
}

func parseCyclonedxXML(path string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	return parseSBOM(path, reader, cyclonedxxml.Format())
}

func parseSpdxJSON(path string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	return parseSBOM(path, reader, spdx22json.Format())
}

func parseSpdx(path string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	return parseSBOM(path, reader, spdx22tagvalue.Format())
}

func parseSBOM(_ string, reader io.Reader, format sbom.Format) ([]*pkg.Package, []artifact.Relationship, error) {
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
