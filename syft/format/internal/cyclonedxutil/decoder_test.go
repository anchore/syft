package cyclonedxutil

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func Test_missingComponentsDecode(t *testing.T) {
	bom := &cyclonedx.BOM{
		SpecVersion: cyclonedx.SpecVersion1_4,
	}
	bomBytes, _ := json.Marshal(&bom)
	dec := NewDecoder(cyclonedx.BOMFileFormatJSON)

	_, err := dec.Decode(bytes.NewReader(bomBytes))
	assert.NoError(t, err)
}
