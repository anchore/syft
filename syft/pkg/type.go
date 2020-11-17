package pkg

import "github.com/package-url/packageurl-go"

// Type represents a Package Type for or within a language ecosystem (there may be multiple package types within a language ecosystem)
type Type string

const (
	// the full set of supported packages
	UnknownPkg       Type = "UnknownPackage"
	ApkPkg           Type = "apk"
	GemPkg           Type = "gem"
	DebPkg           Type = "deb"
	RpmPkg           Type = "rpm"
	NpmPkg           Type = "npm"
	PythonPkg        Type = "python"
	JavaPkg          Type = "java-archive"
	JenkinsPluginPkg Type = "jenkins-plugin"
	GoModulePkg      Type = "go-module"
)

// AllPkgs represents all supported package types
var AllPkgs = []Type{
	ApkPkg,
	GemPkg,
	DebPkg,
	RpmPkg,
	NpmPkg,
	PythonPkg,
	JavaPkg,
	JenkinsPluginPkg,
	GoModulePkg,
}

// PackageURLType returns the PURL package type for the current package.
func (t Type) PackageURLType() string {
	switch t {
	case ApkPkg:
		return "alpine"
	case GemPkg:
		return packageurl.TypeGem
	case DebPkg:
		return "deb"
	case PythonPkg:
		return packageurl.TypePyPi
	case NpmPkg:
		return packageurl.TypeNPM
	case JavaPkg, JenkinsPluginPkg:
		return packageurl.TypeMaven
	case RpmPkg:
		return packageurl.TypeRPM
	case GoModulePkg:
		return packageurl.TypeGolang
	default:
		// TODO: should this be a "generic" purl type instead?
		return ""
	}
}
