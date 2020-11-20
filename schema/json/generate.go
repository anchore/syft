package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/alecthomas/jsonschema"
	jsonPresenter "github.com/anchore/syft/syft/presenter/json"
)

/*
This method of creating the JSON schema only captures strongly typed fields for the purpose of integrations between syft
JSON output and integrations. The downside to this approach is that any values and types used on weakly typed fields
are not captured (empty interfaces). This means that pkg.Package.Metadata is not validated at this time. This approach
can be extended to include specific package metadata struct shapes in the future.
*/

func main() {
	j := jsonschema.Reflect(&jsonPresenter.Document{})
	filename := "schema.json"
	fh, err := os.OpenFile("schema.json", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		panic(err)
	}
	enc := json.NewEncoder(fh)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err = enc.Encode(&j)
	if err != nil {
		panic(err)
	}
	fmt.Printf("wrote new schema to %q\n", filename)
}
