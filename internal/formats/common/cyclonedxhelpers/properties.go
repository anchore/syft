package cyclonedxhelpers

import (
	"fmt"
	"reflect"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
)

func Properties(p pkg.Package) *[]cyclonedx.Property {
	if hasMetadata(p) {
		return getCycloneDXProperties(p.Metadata)
	}
	return nil
}

func getCycloneDXProperties(m interface{}) *[]cyclonedx.Property {
	props := []cyclonedx.Property{}
	structValue := reflect.ValueOf(m)
	structType := structValue.Type()
	for i := 0; i < structValue.NumField(); i++ {
		if name, value := getCycloneDXPropertyName(structType.Field(i)), getCycloneDXPropertyValue(structValue.Field(i)); name != "" && value != "" {
			props = append(props, cyclonedx.Property{
				Name:  name,
				Value: value,
			})
		}
	}
	if len(props) > 0 {
		return &props
	}
	return nil
}

func getCycloneDXPropertyName(field reflect.StructField) string {
	if value, exists := field.Tag.Lookup("cyclonedx"); exists {
		return value
	}
	return ""
}

func getCycloneDXPropertyValue(field reflect.Value) string {
	if field.IsZero() {
		return ""
	}
	return fmt.Sprint(field.Interface())
}
