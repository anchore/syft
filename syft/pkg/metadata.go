package pkg

// MetadataType represents the data shape stored within pkg.Package.Metadata.
type MetadataType string

const (
	// this is the full set of data shapes that can be represented within the pkg.Package.Metadata field
	UnknownMetadataType        MetadataType = "UnknownMetadata"
	ApkMetadataType            MetadataType = "ApkMetadata"
	DpkgMetadataType           MetadataType = "DpkgMetadata"
	GemMetadataType            MetadataType = "GemMetadata"
	JavaMetadataType           MetadataType = "JavaMetadata"
	NpmPackageJSONMetadataType MetadataType = "NpmPackageJsonMetadata"
	RpmdbMetadataType          MetadataType = "RpmdbMetadata"
	PythonPackageMetadataType  MetadataType = "PythonPackageMetadata"
	RustCrateMetadataType      MetadataType = "RustCrateMetadata"
)
