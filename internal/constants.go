package internal

const (
	// JSONSchemaVersion is the current schema version output by the JSON encoder
	// This is roughly following the "SchemaVer" guidelines for versioning the JSON schema. Please see schema/json/README.md for details on how to increment.
	JSONSchemaVersion = "16.1.10"

	// Changelog
	// 16.1.0 - reformulated the python pdm fields (added "URL" and removed the unused "path" field).
	// 16.1.1 - correct elf package osCpe field according to the document of systemd (also add appCpe field)
	// 16.1.2 - placeholder for 16.1.2 changelog
	// 16.1.3 - add GGUFFileParts to GGUFFileHeader metadata
	// 16.1.4 - add BunLockEntry metadata type for bun.lock support
	// 16.1.5 - add DenoLockEntry and DenoRemoteLockEntry metadata types for deno.lock support
	// 16.1.6 - add Dependencies to ElixirMixLockEntry metadata
	// 16.1.7 - add AppleAppBundleEntry metadata type for the apple app bundle cataloger
	// 16.1.8 - add VcpkgManifest metadata type for vcpkg manifest support
	// 16.1.9 - add Symbols (grouped by owning package import path) to GolangBinaryBuildinfoEntry metadata
	// 16.1.10 - add packager and url fields to RPM metadata (RpmDBEntry/RpmArchive)
)
