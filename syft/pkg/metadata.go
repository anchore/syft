package pkg

import (
	"reflect"
)

// MetadataType represents the data shape stored within pkg.Package.Metadata.
type MetadataType string

const (
	// this is the full set of data shapes that can be represented within the pkg.Package.Metadata field

	UnknownMetadataType          MetadataType = "UnknownMetadata"
	ApkMetadataType              MetadataType = "ApkMetadata"
	DpkgMetadataType             MetadataType = "DpkgMetadata"
	GemMetadataType              MetadataType = "GemMetadata"
	JavaMetadataType             MetadataType = "JavaMetadata"
	NpmPackageJSONMetadataType   MetadataType = "NpmPackageJsonMetadata"
	RpmdbMetadataType            MetadataType = "RpmdbMetadata"
	DartPubMetadataType          MetadataType = "DartPubMetadata"
	PythonPackageMetadataType    MetadataType = "PythonPackageMetadata"
	RustCargoPackageMetadataType MetadataType = "RustCargoPackageMetadata"
	KbPackageMetadataType        MetadataType = "KbPackageMetadata"
	GolangBinMetadataType        MetadataType = "GolangBinMetadata"
	PhpComposerJSONMetadataType  MetadataType = "PhpComposerJsonMetadata"
)

var AllMetadataTypes = []MetadataType{
	ApkMetadataType,
	DpkgMetadataType,
	GemMetadataType,
	JavaMetadataType,
	NpmPackageJSONMetadataType,
	RpmdbMetadataType,
	DartPubMetadataType,
	PythonPackageMetadataType,
	RustCargoPackageMetadataType,
	KbPackageMetadataType,
	GolangBinMetadataType,
	PhpComposerJSONMetadataType,
}

var MetadataTypeByName = map[MetadataType]reflect.Type{
	ApkMetadataType:              reflect.TypeOf(ApkMetadata{}),
	DpkgMetadataType:             reflect.TypeOf(DpkgMetadata{}),
	GemMetadataType:              reflect.TypeOf(GemMetadata{}),
	JavaMetadataType:             reflect.TypeOf(JavaMetadata{}),
	NpmPackageJSONMetadataType:   reflect.TypeOf(NpmPackageJSONMetadata{}),
	RpmdbMetadataType:            reflect.TypeOf(RpmdbMetadata{}),
	DartPubMetadataType:          reflect.TypeOf(DartPubMetadata{}),
	PythonPackageMetadataType:    reflect.TypeOf(PythonPackageMetadata{}),
	RustCargoPackageMetadataType: reflect.TypeOf(CargoMetadata{}),
	KbPackageMetadataType:        reflect.TypeOf(KbPackageMetadata{}),
	GolangBinMetadataType:        reflect.TypeOf(GolangBinMetadata{}),
	PhpComposerJSONMetadataType:  reflect.TypeOf(PhpComposerJSONMetadata{}),
}
