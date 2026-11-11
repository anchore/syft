package helpers

import (
	"reflect"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/file"
)

const executableIdentifiersPrefix = "syft:file:executable:identifiers"

// EncodeExecutableIdentifiers encodes the build identifiers of an executable as CycloneDX properties for its
// file component. It returns nil when there are none, so the component has no properties field.
func EncodeExecutableIdentifiers(executable file.Executable) *[]cyclonedx.Property {
	if len(executable.Identifiers) == 0 {
		return nil
	}
	props := EncodeProperties(executable.Identifiers, executableIdentifiersPrefix)
	if len(props) == 0 {
		return nil
	}
	return &props
}

func decodeExecutableIdentifiers(properties *[]cyclonedx.Property) []file.ExecutableIdentifier {
	if properties == nil {
		return nil
	}
	values := map[string]string{}
	for _, p := range *properties {
		values[p.Name] = p.Value
	}
	ids, _ := Decode(reflect.TypeFor[[]file.ExecutableIdentifier](), values, executableIdentifiersPrefix, CycloneDXFields).([]file.ExecutableIdentifier)
	return ids
}
