package cyclonedxhelpers

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func encodeComponent(p pkg.Package) cyclonedx.Component {
	return cyclonedx.Component{
		Type:               cyclonedx.ComponentTypeLibrary,
		Name:               p.Name,
		Group:              encodeGroup(p),
		Version:            p.Version,
		PackageURL:         p.PURL,
		Licenses:           encodeLicenses(p),
		CPE:                encodeCPE(p),
		Author:             encodeAuthor(p),
		Publisher:          encodePublisher(p),
		Description:        encodeDescription(p),
		ExternalReferences: encodeExternalReferences(p),
		Properties:         encodeProperties(p),
	}
}

func hasMetadata(p pkg.Package) bool {
	return p.Metadata != nil
}

func decodeComponent(c *cyclonedx.Component) *pkg.Package {
	typ := pkg.Type(prop(c, "type"))
	purl := c.PackageURL
	if typ == "" && purl != "" {
		typ = pkg.TypeFromPURL(purl)
	}

	metaType, meta := decodePackageMetadata(c)

	p := &pkg.Package{
		Name:         c.Name,
		Version:      c.Version,
		FoundBy:      prop(c, "foundBy"),
		Locations:    decodeLocations(c),
		Licenses:     decodeLicenses(c),
		Language:     pkg.Language(prop(c, "language")),
		Type:         typ,
		CPEs:         decodeCPEs(c),
		PURL:         purl,
		MetadataType: metaType,
		Metadata:     meta,
	}

	allProps := serializeProps(c)
	log.Info(allProps)

	return p
}

func decodeLocations(c *cyclonedx.Component) (out []source.Location) {
	if c.Properties != nil {
		props := *c.Properties
		for i := 0; i < len(props)-1; i++ {
			if props[i].Name == "path" && props[i+1].Name == "layerID" {
				out = append(out, source.Location{
					Coordinates: source.Coordinates{
						RealPath:     props[i].Value,
						FileSystemID: props[i+1].Value,
					},
				})
				i++
			}
		}
	}
	return
}

func serializeProps(c *cyclonedx.Component) string {
	data, _ := json.Marshal(c.Properties)
	return string(data)
}

func mapAllProps(c *cyclonedx.Component, obj reflect.Value) {
	allProps := serializeProps(c)
	log.Info(allProps)

	value := obj
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}

	structType := value.Type()
	if structType.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < value.NumField(); i++ {
		field := structType.Field(i)
		fieldType := field.Type
		fieldValue := value.Field(i)

		name, mapped := field.Tag.Lookup("cyclonedx")
		if !mapped {
			continue
		}

		if fieldType.Kind() == reflect.Ptr {
			fieldType = fieldType.Elem()
			if fieldValue.IsNil() {
				newValue := reflect.New(fieldType)
				fieldValue.Set(newValue)
			}
			fieldValue = fieldValue.Elem()
		}

		incoming := prop(c, name)
		switch fieldType.Kind() {
		case reflect.String:
			if fieldValue.CanSet() {
				fieldValue.SetString(incoming)
			} else {
				msg := fmt.Sprintf("unable to set field: %s.%s", structType.Name(), field.Name)
				log.Info(msg)
			}
		case reflect.Bool:
			if b, err := strconv.ParseBool(incoming); err == nil {
				fieldValue.SetBool(b)
			}
		case reflect.Int:
			if i, err := strconv.Atoi(incoming); err == nil {
				fieldValue.SetInt(int64(i))
			}
		case reflect.Float32, reflect.Float64:
			if i, err := strconv.ParseFloat(incoming, 64); err == nil {
				fieldValue.SetFloat(float64(i))
			}
		case reflect.Struct:
			mapAllProps(c, fieldValue)
		case reflect.Complex128, reflect.Complex64:
			fallthrough
		case reflect.Ptr:
			msg := fmt.Sprintf("decoding CycloneDX properties to a pointer is not supported: %s.%s", field.Type.Name(), field.Name)
			log.Warnf(msg)
		}
	}
}

func decodePackageMetadata(c *cyclonedx.Component) (pkg.MetadataType, interface{}) {
	if c.Properties != nil {
		typ := pkg.MetadataType(prop(c, "metadataType"))
		if typ != "" {
			meta := reflect.New(pkg.MetadataTypeByName[typ])
			metaPtr := meta.Interface()

			// Map all dynamic properties
			mapAllProps(c, meta.Elem())

			// Map all explicit metadata properties
			decodeAuthor(c.Author, metaPtr)
			decodeGroup(c.Group, metaPtr)
			decodePublisher(c.Publisher, metaPtr)
			decodeDescription(c.Description, metaPtr)
			decodeExternalReferences(c, metaPtr)

			// return the actual interface{} | struct ( not interface{} | *struct )
			return typ, meta.Elem().Interface()
		}
	}

	return pkg.UnknownMetadataType, nil
}
