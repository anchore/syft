package pkg

import "github.com/anchore/packageurl-go"

// Type represents a Package Type for or within a language ecosystem (there may be multiple package types within a language ecosystem)
type Type string

const (
	// the full set of supported packages
	UnknownPkg       Type = "UnknownPackage"
	BinaryPkg        Type = "binary"
	ApkPkg           Type = "apk"
	AlpmPkg          Type = "alpm"
	GemPkg           Type = "gem"
	DebPkg           Type = "deb"
	RpmPkg           Type = "rpm"
	NpmPkg           Type = "npm"
	PythonPkg        Type = "python"
	PhpComposerPkg   Type = "php-composer"
	JavaPkg          Type = "java-archive"
	JenkinsPluginPkg Type = "jenkins-plugin"
	GoModulePkg      Type = "go-module"
	RustPkg          Type = "rust-crate"
	KbPkg            Type = "msrc-kb"
	DartPubPkg       Type = "dart-pub"
	DotnetPkg        Type = "dotnet"
	CocoapodsPkg     Type = "pod"
	ConanPkg         Type = "conan"
	PortagePkg       Type = "portage"
	HackagePkg       Type = "hackage"
)

// AllPkgs represents all supported package types
var AllPkgs = []Type{
	ApkPkg,
	AlpmPkg,
	BinaryPkg,
	GemPkg,
	DebPkg,
	RpmPkg,
	NpmPkg,
	PythonPkg,
	PhpComposerPkg,
	JavaPkg,
	JenkinsPluginPkg,
	GoModulePkg,
	RustPkg,
	KbPkg,
	DartPubPkg,
	DotnetPkg,
	CocoapodsPkg,
	ConanPkg,
	PortagePkg,
	HackagePkg,
}

// PackageURLType returns the PURL package type for the current package.
func (t Type) PackageURLType() string {
	switch t {
	case ApkPkg:
		return "alpine"
	case AlpmPkg:
		return "alpm"
	case GemPkg:
		return packageurl.TypeGem
	case DebPkg:
		return "deb"
	case PythonPkg:
		return packageurl.TypePyPi
	case PhpComposerPkg:
		return packageurl.TypeComposer
	case NpmPkg:
		return packageurl.TypeNPM
	case JavaPkg, JenkinsPluginPkg:
		return packageurl.TypeMaven
	case RpmPkg:
		return packageurl.TypeRPM
	case GoModulePkg:
		return packageurl.TypeGolang
	case RustPkg:
		return "cargo"
	case DartPubPkg:
		return packageurl.TypePub
	case DotnetPkg:
		return packageurl.TypeDotnet
	case CocoapodsPkg:
		return packageurl.TypeCocoapods
	case ConanPkg:
		return packageurl.TypeConan
	case PortagePkg:
		return "portage"
	case HackagePkg:
		return packageurl.TypeHackage
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

	return TypeByName(purl.Type)
}

func TypeByName(name string) Type {
	switch name {
	case packageurl.TypeDebian, "deb":
		return DebPkg
	case packageurl.TypeRPM:
		return RpmPkg
	case "alpm":
		return AlpmPkg
	case "alpine":
		return ApkPkg
	case packageurl.TypeMaven:
		return JavaPkg
	case packageurl.TypeComposer:
		return PhpComposerPkg
	case packageurl.TypeGolang:
		return GoModulePkg
	case packageurl.TypeNPM:
		return NpmPkg
	case packageurl.TypePyPi:
		return PythonPkg
	case packageurl.TypeGem:
		return GemPkg
	case "cargo", "crate":
		return RustPkg
	case packageurl.TypePub:
		return DartPubPkg
	case packageurl.TypeDotnet:
		return DotnetPkg
	case packageurl.TypeCocoapods:
		return CocoapodsPkg
	case packageurl.TypeConan:
		return ConanPkg
	case packageurl.TypeHackage:
		return HackagePkg
	case "portage":
		return PortagePkg
	default:
		return UnknownPkg
	}
}
