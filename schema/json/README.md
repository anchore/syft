# JSON Schema

This is the JSON schema for output from the JSON presenters (`syft packages <img> -o json`). The required inputs for defining the JSON schema are as follows:

- the value of `internal.JSONSchemaVersion` that governs the schema filename
- the `Document` struct definition within `github.com/anchore/syft/syft/formats/syftjson/model/document.go` that governs the overall document shape
- generated `AllTypes()` helper function within the `syft/internal/sourcemetadata` and `syft/internal/packagemetadata` packages

With regard to testing the JSON schema, integration test cases provided by the developer are used as examples to validate that JSON output from Syft is always valid relative to the `schema/json/schema-$VERSION.json` file.

## Versioning

Versioning the JSON schema must be done manually by changing the `JSONSchemaVersion` constant within `internal/constants.go`.

This schema is being versioned based off of the "SchemaVer" guidelines, which slightly diverges from Semantic Versioning to tailor for the purposes of data models. 

Given a version number format `MODEL.REVISION.ADDITION`:

- `MODEL`: increment when you make a breaking schema change which will prevent interaction with any historical data
- `REVISION`: increment when you make a schema change which may prevent interaction with some historical data
- `ADDITION`: increment when you make a schema change that is compatible with all historical data

## Adding a New `pkg.*Metadata` Type

When adding a new `pkg.*Metadata` that is assigned to the `pkg.Package.Metadata` struct field you must add a test case to `cmd/syft/internal/test/integration/catalog_packages_cases_test.go` that exercises the new package type with the new metadata.

Additionally it is important to generate a new JSON schema since the `pkg.Package.Metadata` field is covered by the schema.

## Generating a New Schema

Create the new schema by running `make generate-json-schema` from the root of the repo:

- If there is **not** an existing schema for the given version, then the new schema file will be written to `schema/json/schema-$VERSION.json`
- If there is an existing schema for the given version and the new schema matches the existing schema, no action is taken
- If there is an existing schema for the given version and the new schema **does not** match the existing schema, an error is shown indicating to increment the version appropriately (see the "Versioning" section)

***Note: never delete a JSON schema and never change an existing JSON schema once it has been published in a release!*** Only add new schemas with a newly incremented version. All previous schema files must be stored in the `schema/json/` directory.
