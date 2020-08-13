package pkg

// Type represents a Package Type for or within a language ecosystem (there may be multiple package types within a language ecosystem)
type Type string

const (
	UnknownPkg Type = "UnknownPackage"
	ApkPkg     Type = "apk"
	BundlerPkg Type = "bundle"
	DebPkg     Type = "deb"
	EggPkg     Type = "egg"
	// PacmanPkg Type = "pacman"
	RpmPkg                Type = "rpm"
	WheelPkg              Type = "wheel"
	PoetryPkg             Type = "poetry"
	NpmPkg                Type = "npm"
	YarnPkg               Type = "yarn"
	PythonRequirementsPkg Type = "python-requirements"
	JavaPkg               Type = "java-archive"
	JenkinsPluginPkg      Type = "jenkins-plugin"
	GoModulePkg           Type = "go-module"
)

var AllPkgs = []Type{
	ApkPkg,
	BundlerPkg,
	DebPkg,
	EggPkg,
	// PacmanPkg,
	RpmPkg,
	WheelPkg,
	NpmPkg,
	YarnPkg,
	PythonRequirementsPkg,
	JavaPkg,
	JenkinsPluginPkg,
	GoModulePkg,
}
