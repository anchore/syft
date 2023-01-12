package pkg

import (
	"reflect"
)

// MetadataType represents the data shape stored within pkg.Package.Metadata.
type MetadataType string

const (
	// this is the full set of data shapes that can be represented within the pkg.Package.Metadata field
	UnknownMetadataType            MetadataType = "UnknownMetadata"
	AlpmMetadataType               MetadataType = "AlpmMetadata"
	ApkMetadataType                MetadataType = "ApkMetadata"
	BinaryMetadataType             MetadataType = "BinaryMetadata"
	CocoapodsMetadataType          MetadataType = "CocoapodsMetadataType"
	ConanLockMetadataType          MetadataType = "ConanLockMetadataType"
	ConanMetadataType              MetadataType = "ConanMetadataType"
	DartPubMetadataType            MetadataType = "DartPubMetadata"
	DotnetDepsMetadataType         MetadataType = "DotnetDepsMetadata"
	DpkgMetadataType               MetadataType = "DpkgMetadata"
	GemMetadataType                MetadataType = "GemMetadata"
	GolangMetadataType             MetadataType = "GolangMetadata"
	HackageMetadataType            MetadataType = "HackageMetadataType"
	JavaMetadataType               MetadataType = "JavaMetadata"
	KbPackageMetadataType          MetadataType = "KbPackageMetadata"
	MixLockMetadataType            MetadataType = "MixLockMetadataType"
	NpmPackageJSONMetadataType     MetadataType = "NpmPackageJsonMetadata"
	NpmPackageLockJSONMetadataType MetadataType = "NpmPackageLockJsonMetadata"
	PhpComposerJSONMetadataType    MetadataType = "PhpComposerJsonMetadata"
	PortageMetadataType            MetadataType = "PortageMetadata"
	PythonPackageMetadataType      MetadataType = "PythonPackageMetadata"
	PythonPipfileLockMetadataType  MetadataType = "PythonPipfileLockMetadata"
	RebarLockMetadataType          MetadataType = "RebarLockMetadataType"
	RpmMetadataType                MetadataType = "RpmMetadata"
	RustCargoPackageMetadataType   MetadataType = "RustCargoPackageMetadata"
)

var AllMetadataTypes = []MetadataType{
	AlpmMetadataType,
	ApkMetadataType,
	BinaryMetadataType,
	CocoapodsMetadataType,
	ConanLockMetadataType,
	ConanMetadataType,
	DartPubMetadataType,
	DotnetDepsMetadataType,
	DpkgMetadataType,
	GemMetadataType,
	GolangMetadataType,
	HackageMetadataType,
	JavaMetadataType,
	KbPackageMetadataType,
	MixLockMetadataType,
	NpmPackageJSONMetadataType,
	NpmPackageLockJSONMetadataType,
	PhpComposerJSONMetadataType,
	PortageMetadataType,
	PythonPackageMetadataType,
	PythonPipfileLockMetadataType,
	RebarLockMetadataType,
	RpmMetadataType,
	RustCargoPackageMetadataType,
}

var MetadataTypeByName = map[MetadataType]reflect.Type{
	AlpmMetadataType:               reflect.TypeOf(AlpmMetadata{}),
	ApkMetadataType:                reflect.TypeOf(ApkMetadata{}),
	BinaryMetadataType:             reflect.TypeOf(BinaryMetadata{}),
	CocoapodsMetadataType:          reflect.TypeOf(CocoapodsMetadata{}),
	ConanLockMetadataType:          reflect.TypeOf(ConanLockMetadata{}),
	ConanMetadataType:              reflect.TypeOf(ConanMetadata{}),
	DartPubMetadataType:            reflect.TypeOf(DartPubMetadata{}),
	DotnetDepsMetadataType:         reflect.TypeOf(DotnetDepsMetadata{}),
	DpkgMetadataType:               reflect.TypeOf(DpkgMetadata{}),
	GemMetadataType:                reflect.TypeOf(GemMetadata{}),
	GolangMetadataType:             reflect.TypeOf(GolangMetadata{}),
	HackageMetadataType:            reflect.TypeOf(HackageMetadata{}),
	JavaMetadataType:               reflect.TypeOf(JavaMetadata{}),
	KbPackageMetadataType:          reflect.TypeOf(KbPackageMetadata{}),
	MixLockMetadataType:            reflect.TypeOf(MixLockMetadata{}),
	NpmPackageJSONMetadataType:     reflect.TypeOf(NpmPackageJSONMetadata{}),
	NpmPackageLockJSONMetadataType: reflect.TypeOf(NpmPackageLockJSONMetadata{}),
	PhpComposerJSONMetadataType:    reflect.TypeOf(PhpComposerJSONMetadata{}),
	PortageMetadataType:            reflect.TypeOf(PortageMetadata{}),
	PythonPackageMetadataType:      reflect.TypeOf(PythonPackageMetadata{}),
	PythonPipfileLockMetadataType:  reflect.TypeOf(PythonPipfileLockMetadata{}),
	RebarLockMetadataType:          reflect.TypeOf(RebarLockMetadata{}),
	RpmMetadataType:                reflect.TypeOf(RpmMetadata{}),
	RustCargoPackageMetadataType:   reflect.TypeOf(CargoPackageMetadata{}),
}

func CleanMetadataType(typ MetadataType) MetadataType {
	if typ == "RpmdbMetadata" {
		return RpmMetadataType
	}
	if typ == "GolangBinMetadata" {
		return GolangMetadataType
	}
	return typ
}
