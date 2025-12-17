package internal

const (
	// JSONSchemaVersion is the current schema version output by the JSON encoder
	// This is roughly following the "SchemaVer" guidelines for versioning the JSON schema. Please see schema/json/README.md for details on how to increment.
	JSONSchemaVersion = "16.1.2"

	// Changelog
	// 16.1.0 - reformulated the python pdm fields (added "URL" and removed the unused "path" field).
	// 16.1.1 - correct elf package osCpe field according to the document of systemd (also add appCpe field)

)
