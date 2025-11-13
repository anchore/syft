package pkg

import (
	"github.com/anchore/packageurl-go"
)

// Type represents a Package Type for or within a language ecosystem (there may be multiple package types within a language ecosystem)
type Type string

func (t Type) String() string {
	return string(t)
}

const (
	// the full set of supported packages
	UnknownPkg              Type = "UnknownPackage"
	AlpmPkg                 Type = "alpm"
	ApkPkg                  Type = "apk"
	BinaryPkg               Type = "binary"
	BitnamiPkg              Type = "bitnami"
	CocoapodsPkg            Type = "pod"
	ConanPkg                Type = "conan"
	CondaPkg                Type = "conda"
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
	OpamPkg                 Type = "opam"
	PhpComposerPkg          Type = "php-composer"
	PhpPeclPkg              Type = "php-pecl" // Deprecated: will be removed in syft v2.0
	PhpPearPkg              Type = "php-pear"
	PortagePkg              Type = "portage"
	PythonPkg               Type = "python"
	Rpkg                    Type = "R-package"
	LuaRocksPkg             Type = "lua-rocks"
	RpmPkg                  Type = "rpm"
	RustPkg                 Type = "rust-crate"
	SwiftPkg                Type = "swift"
	SwiplPackPkg            Type = "swiplpack"
	TerraformPkg            Type = "terraform"
	WordpressPluginPkg      Type = "wordpress-plugin"
	HomebrewPkg             Type = "homebrew"
	ModelPkg                Type = "model"
)

// AllPkgs represents all supported package types
var AllPkgs = []Type{
	AlpmPkg,
	ApkPkg,
	BinaryPkg,
	BitnamiPkg,
	CocoapodsPkg,
	ConanPkg,
	CondaPkg,
	DartPubPkg,
	DebPkg,
	DotnetPkg,
	ErlangOTPPkg,
	GemPkg,
	GithubActionPkg,
	GithubActionWorkflowPkg,
	GraalVMNativeImagePkg,
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
	OpamPkg,
	PhpComposerPkg,
	PhpPeclPkg,
	PhpPearPkg,
	PortagePkg,
	PythonPkg,
	Rpkg,
	LuaRocksPkg,
	RpmPkg,
	RustPkg,
	SwiftPkg,
	SwiplPackPkg,
	TerraformPkg,
	WordpressPluginPkg,
	HomebrewPkg,
	ModelPkg,
}

// PackageURLType returns the PURL package type for the current package.
//
//nolint:funlen, gocyclo
func (t Type) PackageURLType() string {
	switch t {
	case AlpmPkg:
		return "alpm"
	case ApkPkg:
		return packageurl.TypeAlpine
	case BitnamiPkg:
		return packageurl.TypeBitnami
	case CocoapodsPkg:
		return packageurl.TypeCocoapods
	case ConanPkg:
		return packageurl.TypeConan
	case CondaPkg:
		return packageurl.TypeGeneric
	case DartPubPkg:
		return packageurl.TypePub
	case DebPkg:
		return "deb"
	case DotnetPkg:
		return "dotnet"
	case ErlangOTPPkg:
		return packageurl.TypeOTP
	case GemPkg:
		return packageurl.TypeGem
	case HexPkg:
		return packageurl.TypeHex
	case GithubActionPkg, GithubActionWorkflowPkg:
		// note: this is not a real purl type, but it is the closest thing we have for now
		return packageurl.TypeGithub
	case GoModulePkg:
		return packageurl.TypeGolang
	case HackagePkg:
		return packageurl.TypeHackage
	case JavaPkg, JenkinsPluginPkg:
		return packageurl.TypeMaven
	case LinuxKernelPkg:
		return "generic/linux-kernel"
	case LinuxKernelModulePkg:
		return packageurl.TypeGeneric
	case PhpComposerPkg:
		return packageurl.TypeComposer
	case PhpPearPkg, PhpPeclPkg:
		return "pear"
	case PythonPkg:
		return packageurl.TypePyPi
	case PortagePkg:
		return "portage"
	case LuaRocksPkg:
		return packageurl.TypeLuaRocks
	case NixPkg:
		return "nix"
	case NpmPkg:
		return packageurl.TypeNPM
	case OpamPkg:
		return "opam"
	case Rpkg:
		return packageurl.TypeCran
	case RpmPkg:
		return packageurl.TypeRPM
	case RustPkg:
		return "cargo"
	case SwiftPkg:
		return packageurl.TypeSwift
	case SwiplPackPkg:
		return "swiplpack"
	case TerraformPkg:
		return "terraform"
	case WordpressPluginPkg:
		return "wordpress-plugin"
	case HomebrewPkg:
		return "homebrew"
	default:
		// TODO: should this be a "generic" purl type instead?
		return ""
	}
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

//nolint:funlen,gocyclo
func TypeByName(name string) Type {
	switch name {
	case "alpm":
		return AlpmPkg
	case packageurl.TypeAlpine, "alpine":
		return ApkPkg
	case packageurl.TypeBitnami:
		return BitnamiPkg
	case packageurl.TypeDebian:
		return DebPkg
	case packageurl.TypeComposer:
		return PhpComposerPkg
	case "pear", "pecl":
		return PhpPearPkg
	case packageurl.TypeGolang:
		return GoModulePkg
	case packageurl.TypeGem:
		return GemPkg
	case "cargo", "crate":
		return RustPkg
	case "conda":
		return CondaPkg
	case packageurl.TypePub:
		return DartPubPkg
	case "dotnet": // here to support legacy use cases
		return DotnetPkg
	case packageurl.TypeCocoapods:
		return CocoapodsPkg
	case packageurl.TypeConan:
		return ConanPkg
	case packageurl.TypeHackage:
		return HackagePkg
	case packageurl.TypeHex:
		return HexPkg
	case packageurl.TypeLuaRocks:
		return LuaRocksPkg
	case packageurl.TypeMaven:
		return JavaPkg
	case packageurl.TypeNPM:
		return NpmPkg
	case packageurl.TypePyPi:
		return PythonPkg
	case "portage":
		return PortagePkg
	case packageurl.TypeOTP:
		return ErlangOTPPkg
	case "linux-kernel":
		return LinuxKernelPkg
	case "linux-kernel-module":
		return LinuxKernelModulePkg
	case "nix":
		return NixPkg
	case "opam":
		return OpamPkg
	case packageurl.TypeCran:
		return Rpkg
	case packageurl.TypeRPM:
		return RpmPkg
	case packageurl.TypeSwift:
		return SwiftPkg
	case "swiplpack":
		return SwiplPackPkg
	case "terraform":
		return TerraformPkg
	case "wordpress-plugin":
		return WordpressPluginPkg
	case "homebrew":
		return HomebrewPkg
	default:
		return UnknownPkg
	}
}
