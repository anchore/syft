package helpers

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
)

var (
	CycloneDXFields = RequiredTag("cyclonedx")
)

func EncodeProperties(obj interface{}, prefix string) (out []cyclonedx.Property) {
	for _, p := range Sorted(Encode(obj, prefix, CycloneDXFields)) {
		out = append(out, cyclonedx.Property{
			Name:  p.Name,
			Value: p.Value,
		})
	}
	return
}

func decodeProperties(properties []cyclonedx.Property, prefix string) map[string]string {
	labels := make(map[string]string)
	for _, property := range properties {
		if strings.HasPrefix(property.Name, prefix) {
			labelName := strings.TrimPrefix(property.Name, prefix)
			labels[labelName] = property.Value
		}
	}
	return labels
}
