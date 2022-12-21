package cyclonedxjson

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/formats/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

func encoder(output io.Writer, s sbom.SBOM) error {
	bom := cyclonedxhelpers.ToFormatModel(s)
	return Encode(bom, output)
}

// Encode encodes the CycloneDX BOM to JSON, exported so Grype can use this
func Encode(bom *cyclonedx.BOM, output io.Writer) error {
	if bom.SpecVersion < cyclonedx.SpecVersion1_2 {
		return fmt.Errorf("json format is not supported for specification versions lower than %s", cyclonedx.SpecVersion1_2)
	}

	e := json.NewEncoder(output)
	e.SetIndent("", " ")
	e.SetEscapeHTML(false)

	return e.Encode(bom)
}
