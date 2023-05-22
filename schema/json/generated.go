package main

import "github.com/anchore/syft/syft/pkg"

type artifactMetadataContainer struct {
	Alpm               pkg.AlpmMetadata
	Apk                pkg.ApkMetadata
	Binary             pkg.BinaryMetadata
	Cocopods           pkg.CocoapodsMetadata
	Conan              pkg.ConanMetadata
	ConanLock          pkg.ConanLockMetadata
	Dart               pkg.DartPubMetadata
	Dotnet             pkg.DotnetDepsMetadata
	Dpkg               pkg.DpkgMetadata
	Gem                pkg.GemMetadata
	GoBin              pkg.GolangBinMetadata
	GoMod              pkg.GolangModMetadata
	Hackage            pkg.HackageMetadata
	Java               pkg.JavaMetadata
	KbPackage          pkg.KbPackageMetadata
	LinuxKernel        pkg.LinuxKernelMetadata
	LinuxKernelModule  pkg.LinuxKernelModuleMetadata
	Nix                pkg.NixStoreMetadata
	NpmPackage         pkg.NpmPackageJSONMetadata
	NpmPackageLock     pkg.NpmPackageLockJSONMetadata
	MixLock            pkg.MixLockMetadata
	Php                pkg.PhpComposerJSONMetadata
	Portage            pkg.PortageMetadata
	PythonPackage      pkg.PythonPackageMetadata
	PythonPipfilelock  pkg.PythonPipfileLockMetadata
	PythonRequirements pkg.PythonRequirementsMetadata
	RDescriptionFile   pkg.RDescriptionFileMetadata
	Rebar              pkg.RebarLockMetadata
	Rpm                pkg.RpmMetadata
	RustCargo          pkg.CargoPackageMetadata
}
