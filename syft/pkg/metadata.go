package pkg

type MetadataType string

const (
	UnknownMetadataType MetadataType = "UnknownMetadata"
	ApkMetadataType     MetadataType = "apk-metadata"
	DpkgMetadataType    MetadataType = "dpkg-metadata"
	GemgMetadataType    MetadataType = "gem-metadata"
	RpmdbMetadataType   MetadataType = "rpmdb-metadata"
)
