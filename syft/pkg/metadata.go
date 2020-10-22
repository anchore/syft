package pkg

type MetadataType string

const (
	UnknownMetadataType        MetadataType = "UnknownMetadata"
	ApkMetadataType            MetadataType = "apk-metadata"
	DpkgMetadataType           MetadataType = "dpkg-metadata"
	GemMetadataType            MetadataType = "gem-metadata"
	JavaMetadataType           MetadataType = "java-metadata"
	NpmPackageJSONMetadataType MetadataType = "npm-package-json-metadata"
	RpmdbMetadataType          MetadataType = "rpmdb-metadata"
	PythonPackageMetadataType  MetadataType = "python-package-metadata"
)
