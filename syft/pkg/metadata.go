package pkg

type MetadataType string

const (
	UnknownMetadataType        MetadataType = "UnknownMetadata"
	ApkMetadataType            MetadataType = "apk-metadata"
	DpkgMetadataType           MetadataType = "dpkg-metadata"
	GemMetadataType            MetadataType = "gem-metadata"
	JavaMetadataType           MetadataType = "java-metadata"
	NpmPackageJsonMetadataType MetadataType = "npm-package-json-metadata"
	RpmdbMetadataType          MetadataType = "rpmdb-metadata"
	PythonEggWheelMetadataType MetadataType = "python-egg-wheel-metadata"
)
