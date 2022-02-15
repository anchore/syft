package cyclonedxhelpers

import (
	"fmt"
	"reflect"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
)

func Properties(p pkg.Package) *[]cyclonedx.Property {
	props := []cyclonedx.Property{}
	props = append(props, *getCycloneDXProperties(p)...)
	if len(p.Locations) > 0 {
		for _, l := range p.Locations {
			props = append(props, *getCycloneDXProperties(l.Coordinates)...)
		}
	}
	if hasMetadata(p) {
		props = append(props, *getCycloneDXProperties(p.Metadata)...)
	}
	if len(props) > 0 {
		return &props
	}
	return nil
}

func getCycloneDXProperties(m interface{}) *[]cyclonedx.Property {
	props := []cyclonedx.Property{}
	structValue := reflect.ValueOf(m)
	if structValue.Kind() != reflect.Struct {
		return &props
	}
	structType := structValue.Type()
	for i := 0; i < structValue.NumField(); i++ {
		if name, value := getCycloneDXPropertyName(structType.Field(i)), getCycloneDXPropertyValue(structValue.Field(i)); name != "" && value != "" {
			// In the case of the value is a struct and has cyclonedx tag with name "-"
			// call the getCycloneDXProperties recursively.
			if name == "-" && reflect.ValueOf(value).Kind() == reflect.Struct {
				props = append(props, *getCycloneDXProperties(value)...)
			} else if reflect.ValueOf(value).Kind() == reflect.String {
				props = append(props, cyclonedx.Property{
					Name:  name,
					Value: fmt.Sprint(value),
				})
			}
		}
	}
	return &props
}

func getCycloneDXPropertyName(field reflect.StructField) string {
	if value, exists := field.Tag.Lookup("cyclonedx"); exists {
		return value
	}
	return ""
}

func getCycloneDXPropertyValue(field reflect.Value) interface{} {
	if field.IsZero() {
		return ""
	}
	switch field.Kind() {
	case reflect.String, reflect.Bool, reflect.Int, reflect.Float32, reflect.Float64, reflect.Complex128, reflect.Complex64:
		if field.CanInterface() {
			return fmt.Sprint(field.Interface())
		}
		return ""
	case reflect.Struct:
		if field.CanInterface() {
			return field.Interface()
		}
		return ""
	case reflect.Ptr:
		return getCycloneDXPropertyValue(reflect.Indirect(field))
	}
	return ""
}
