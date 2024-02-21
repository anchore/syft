package sourcemetadata

import (
	"reflect"
	"strings"

	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/anchore/syft/syft/source/filesource"
	"github.com/anchore/syft/syft/source/stereoscopesource"
)

var jsonNameFromType = map[reflect.Type][]string{
	reflect.TypeOf(directorysource.DirectoryMetadata{}): {"directory", "dir"},
	reflect.TypeOf(filesource.FileMetadata{}):           {"file"},
	reflect.TypeOf(stereoscopesource.ImageMetadata{}):   {"image"},
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
