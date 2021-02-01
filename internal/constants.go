package internal

const (
	// ApplicationName is the non-capitalized name of the application (do not change this)
	ApplicationName = "syft"

	// JSONSchemaVersion is the current schema version output by the JSON presenter
	// This is roughly following the "SchemaVer" guidelines for versioning the JSON schema. Please see schema/json/README.md for details on how to increment.
	JSONSchemaVersion = "1.0.1"

	// CPEDictionaryUpdateURL is the official NVD CPE Dictionary URL
	CPEDictionaryUpdateURL = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"
)
