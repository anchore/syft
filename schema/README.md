## Updating the JSON schema
Today the JSON schema is generated from integration test data. Specifically, when integration tests are run, the `/schema/json/examples` directory is populated with syft JSON output data. This examples directory is used to drive automatically generating the JSON schema.
The caveats with this approach is:
1) the JSON schema is only as good as the examples provided
2) there is an integration test that ensures that the JSON schema is valid relative to what the code currently generates.
This means to update the JSON schema you need to
1) Open up `test/integration/json_schema_test.go` and comment out invocations of the `validateAgainstV1Schema` function.
2) From the root of the repo run `generate-json-schema`. Now there should be a new schema generated at `/schema/json/schema.json`
3) Uncomment the `validateAgainstV1Schema` function.