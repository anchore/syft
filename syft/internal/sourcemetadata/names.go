package sourcemetadata

import (
	"reflect"
	"strings"

	"github.com/anchore/syft/syft/source"
)

var jsonNameFromType = map[reflect.Type][]string{
	reflect.TypeOf(source.DirectorySourceMetadata{}):        {"directory", "dir"},
	reflect.TypeOf(source.FileSourceMetadata{}):             {"file"},
	reflect.TypeOf(source.StereoscopeImageSourceMetadata{}): {"image"},
}

func AllNames() []string {
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
			if v == name {
				return t
			}
		}
	}
	return nil
}
