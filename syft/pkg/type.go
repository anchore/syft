package pkg

import (
	"github.com/anchore/packageurl-go"
)

// Type represents a Package Type for or within a language ecosystem (there may be multiple package types within a language ecosystem)
type Type string

const (
	// the full set of supported packages
	UnknownPkg              Type = "UnknownPackage"
	AlpmPkg                 Type = "alpm"
	ApkPkg                  Type = "apk"
	BinaryPkg               Type = "binary"
	BitnamiPkg              Type = "bitnami"
	CocoapodsPkg            Type = "pod"
	ConanPkg                Type = "conan"
	DartPubPkg              Type = "dart-pub"
	DebPkg                  Type = "deb"
	DotnetPkg               Type = "dotnet"
	ErlangOTPPkg            Type = "erlang-otp"
	GemPkg                  Type = "gem"
	GithubActionPkg         Type = "github-action"
	GithubActionWorkflowPkg Type = "github-action-workflow"
	GoModulePkg             Type = "go-module"
	GraalVMNativeImagePkg   Type = "graalvm-native-image"
	HackagePkg              Type = "hackage"
	HexPkg                  Type = "hex"
	JavaPkg                 Type = "java-archive"
	JenkinsPluginPkg        Type = "jenkins-plugin"
	KbPkg                   Type = "msrc-kb"
	LinuxKernelPkg          Type = "linux-kernel"
	LinuxKernelModulePkg    Type = "linux-kernel-module"
	NixPkg                  Type = "nix"
	NpmPkg                  Type = "npm"
	PhpComposerPkg          Type = "php-composer"
	PhpPeclPkg              Type = "php-pecl"
	PortagePkg              Type = "portage"
	PythonPkg               Type = "python"
	Rpkg                    Type = "R-package"
	LuaRocksPkg             Type = "lua-rocks"
	RpmPkg                  Type = "rpm"
	RustPkg                 Type = "rust-crate"
	SwiftPkg                Type = "swift"
	SwiplPackPkg            Type = "swiplpack"
	OpamPkg                 Type = "opam"
	WordpressPluginPkg      Type = "wordpress-plugin"
)

// AllPkgs represents all supported package types
var AllPkgs = []Type{
	AlpmPkg,
	ApkPkg,
	BinaryPkg,
	BitnamiPkg,
	CocoapodsPkg,
	ConanPkg,
	DartPubPkg,
	DebPkg,
	DotnetPkg,
	ErlangOTPPkg,
	GemPkg,
	GithubActionPkg,
	GithubActionWorkflowPkg,
	GoModulePkg,
	HackagePkg,
	HexPkg,
	JavaPkg,
	JenkinsPluginPkg,
	KbPkg,
	LinuxKernelPkg,
	LinuxKernelModulePkg,
	NixPkg,
	NpmPkg,
	PhpComposerPkg,
	PhpPeclPkg,
	PortagePkg,
	PythonPkg,
	Rpkg,
	LuaRocksPkg,
	RpmPkg,
	RustPkg,
	SwiftPkg,
	SwiplPackPkg,
	OpamPkg,
	WordpressPluginPkg,
}

func TypeFromPURL(p string) Type {
	purl, err := packageurl.FromString(p)
	if err != nil {
		return UnknownPkg
	}

	ptype := purl.Type
	if ptype == "generic" {
		ptype = purl.Name
	}
	return TypeByName(ptype)
}

var purlToPkgMap = map[string]Type{
	"alpm":                   AlpmPkg,
	packageurl.TypeAlpine:    ApkPkg,
	"alpine":                 ApkPkg,
	packageurl.TypeDebian:    DebPkg,
	packageurl.TypeRPM:       RpmPkg,
	packageurl.TypeBitnami:   BitnamiPkg,
	packageurl.TypeCocoapods: CocoapodsPkg,
	packageurl.TypeComposer:  PhpComposerPkg,
	packageurl.TypeConan:     ConanPkg,
	"cargo":                  RustPkg,
	"crate":                  RustPkg,
	packageurl.TypeCran:      Rpkg,
	"dotnet":                 DotnetPkg,
	packageurl.TypeGem:       GemPkg,
	packageurl.TypeGolang:    GoModulePkg,
	packageurl.TypeHackage:   HackagePkg,
	packageurl.TypeHex:       HexPkg,
	packageurl.TypeLuaRocks:  LuaRocksPkg,
	packageurl.TypeMaven:     JavaPkg,
	"nix":                    NixPkg,
	packageurl.TypeNPM:       NpmPkg,
	"opam":                   OpamPkg,
	packageurl.TypeOTP:       ErlangOTPPkg,
	"pecl":                   PhpPeclPkg,
	"portage":                PortagePkg,
	packageurl.TypeSwift:     SwiftPkg,
	"swiplpack":              SwiplPackPkg,
	packageurl.TypePub:       DartPubPkg,
	packageurl.TypePyPi:      PythonPkg,
	"wordpress-plugin":       WordpressPluginPkg,
	"linux-kernel":           LinuxKernelPkg,
	"linux-kernel-module":    LinuxKernelModulePkg,
}

// PackageURLType returns the PURL package type for the current package.
func (t Type) PackageURLType() string {
	// First we look for packages types associated to more than one
	// purl type so the response in consistent, and other package types
	// that are not in the map
	switch t {
	case ApkPkg:
		return packageurl.TypeAlpine
	case RustPkg:
		return "cargo"
	case BinaryPkg:
		return "binary"
	case GithubActionPkg, GithubActionWorkflowPkg:
		// note: this is not a real purl type, but it is the closest thing we have for now
		return packageurl.TypeGithub
	case JenkinsPluginPkg:
		return packageurl.TypeMaven
	case LinuxKernelPkg:
		return "generic/linux-kernel"
	case LinuxKernelModulePkg:
		return packageurl.TypeGeneric
	}

	// Then, we check if any element's value in the map corresponds to the
	// given package type
	for k, v := range purlToPkgMap {
		if v == t {
			return k
		}
	}

	// TODO: should this be a "generic" purl type instead?
	return ""
}

func TypeByName(name string) Type {
	// Check if the package type is in the map
	if pkgType, ok := purlToPkgMap[name]; ok {
		return pkgType
	}

	return UnknownPkg
}
