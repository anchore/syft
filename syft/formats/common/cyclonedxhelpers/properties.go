package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/formats/common"
)

var (
	CycloneDXFields = common.RequiredTag("cyclonedx")
)

func encodeProperties(obj interface{}, prefix string) (out []cyclonedx.Property) {
	for _, p := range common.Sorted(common.Encode(obj, prefix, CycloneDXFields)) {
		out = append(out, cyclonedx.Property{
			Name:  p.Name,
			Value: p.Value,
		})
	}
	return
}
