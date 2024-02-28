package sourcemetadata

import (
	"reflect"
	"strings"

	"github.com/anchore/syft/syft/source"
)

var jsonNameFromType = map[reflect.Type][]string{
	reflect.TypeOf(source.DirectoryMetadata{}): {"directory", "dir"},
	reflect.TypeOf(source.FileMetadata{}):      {"file"},
	reflect.TypeOf(source.ImageMetadata{}):     {"image"},
}

func AllTypeNames() []string {
	names := make([]string, 0)
	for _, t := range AllTypes() {
		names = append(names, reflect.TypeOf(t).Name())
	}
	return names
}

func JSONName(metadata any) string {
	if vs, exists := jsonNameFromType[reflect.TypeOf(metadata)]; exists {
		return vs[0]
	}
	return ""
}

func ReflectTypeFromJSONName(name string) reflect.Type {
	name = strings.ToLower(name)
	for t, vs := range jsonNameFromType {
		for _, v := range vs {
			if strings.ToLower(v) == name {
				return t
			}
		}
	}
	return nil
}
