package internal

import (
	"reflect"

	"github.com/anchore/syft/syft/source"
)

// TODO: a future PR can make this more dynamic by code generating this list based on an AST of the source package
// to find all possible metatdata struct types.
func AllSourceMetadataReflectTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(source.StereoscopeImageSourceMetadata{}),
		reflect.TypeOf(source.FileSourceMetadata{}),
		reflect.TypeOf(source.DirectorySourceMetadata{}),
	}
}
