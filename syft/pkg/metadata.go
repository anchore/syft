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
	AlpmMetadataType             MetadataType = "AlpmMetadata"
	DpkgMetadataType             MetadataType = "DpkgMetadata"
	GemMetadataType              MetadataType = "GemMetadata"
	JavaMetadataType             MetadataType = "JavaMetadata"
	NpmPackageJSONMetadataType   MetadataType = "NpmPackageJsonMetadata"
	RpmMetadataType              MetadataType = "RpmMetadata"
	DartPubMetadataType          MetadataType = "DartPubMetadata"
	DotnetDepsMetadataType       MetadataType = "DotnetDepsMetadata"
	PythonPackageMetadataType    MetadataType = "PythonPackageMetadata"
	RustCargoPackageMetadataType MetadataType = "RustCargoPackageMetadata"
	KbPackageMetadataType        MetadataType = "KbPackageMetadata"
	GolangBinMetadataType        MetadataType = "GolangBinMetadata"
	PhpComposerJSONMetadataType  MetadataType = "PhpComposerJsonMetadata"
	CocoapodsMetadataType        MetadataType = "CocoapodsMetadataType"
	ConanaMetadataType           MetadataType = "ConanaMetadataType"
	PortageMetadataType          MetadataType = "PortageMetadata"
	HackageMetadataType          MetadataType = "HackageMetadataType"
)

var AllMetadataTypes = []MetadataType{
	ApkMetadataType,
	AlpmMetadataType,
	DpkgMetadataType,
	GemMetadataType,
	JavaMetadataType,
	NpmPackageJSONMetadataType,
	RpmMetadataType,
	DartPubMetadataType,
	DotnetDepsMetadataType,
	PythonPackageMetadataType,
	RustCargoPackageMetadataType,
	KbPackageMetadataType,
	GolangBinMetadataType,
	PhpComposerJSONMetadataType,
	CocoapodsMetadataType,
	ConanaMetadataType,
	PortageMetadataType,
	HackageMetadataType,
}

var MetadataTypeByName = map[MetadataType]reflect.Type{
	ApkMetadataType:              reflect.TypeOf(ApkMetadata{}),
	AlpmMetadataType:             reflect.TypeOf(AlpmMetadata{}),
	DpkgMetadataType:             reflect.TypeOf(DpkgMetadata{}),
	GemMetadataType:              reflect.TypeOf(GemMetadata{}),
	JavaMetadataType:             reflect.TypeOf(JavaMetadata{}),
	NpmPackageJSONMetadataType:   reflect.TypeOf(NpmPackageJSONMetadata{}),
	RpmMetadataType:              reflect.TypeOf(RpmMetadata{}),
	DartPubMetadataType:          reflect.TypeOf(DartPubMetadata{}),
	DotnetDepsMetadataType:       reflect.TypeOf(DotnetDepsMetadata{}),
	PythonPackageMetadataType:    reflect.TypeOf(PythonPackageMetadata{}),
	RustCargoPackageMetadataType: reflect.TypeOf(CargoMetadata{}),
	KbPackageMetadataType:        reflect.TypeOf(KbPackageMetadata{}),
	GolangBinMetadataType:        reflect.TypeOf(GolangBinMetadata{}),
	PhpComposerJSONMetadataType:  reflect.TypeOf(PhpComposerJSONMetadata{}),
	CocoapodsMetadataType:        reflect.TypeOf(CocoapodsMetadata{}),
	ConanaMetadataType:           reflect.TypeOf(ConanMetadata{}),
	PortageMetadataType:          reflect.TypeOf(PortageMetadata{}),
	HackageMetadataType:          reflect.TypeOf(HackageMetadata{}),
}

func CleanMetadataType(typ MetadataType) MetadataType {
	if typ == "RpmdbMetadata" {
		return RpmMetadataType
	}
	return typ
}
