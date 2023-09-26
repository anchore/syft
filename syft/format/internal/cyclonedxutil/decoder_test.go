package cyclonedxutil

import (
	"encoding/json"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_missingComponentsDecode(t *testing.T) {
	bom := &cyclonedx.BOM{
		SpecVersion: cyclonedx.SpecVersion1_4,
	}
	bomBytes, _ := json.Marshal(&bom)
	dec := NewDecoder(cyclonedx.BOMFileFormatJSON)

	_, err := dec.Decode(bomBytes)
	assert.NoError(t, err)
}
