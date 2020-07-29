package pkg

const (
	UnknownPkg Type = iota
	ApkPkg
	BundlerPkg
	DebPkg
	EggPkg
	//PacmanPkg
	RpmPkg
	WheelPkg
	NpmPkg
	YarnPkg
	PythonRequirementsPkg
	JavaPkg
	JenkinsPluginPkg
	GoModulePkg
)

type Type uint

var typeStr = []string{
	"UnknownPackage",
	"apk",
	"bundle",
	"deb",
	"egg",
	//"pacman",
	"rpm",
	"wheel",
	"npm",
	"yarn",
	"python-requirements",
	"java-archive",
	"jenkins-plugin",
	"go-module",
}

var AllPkgs = []Type{
	ApkPkg,
	BundlerPkg,
	DebPkg,
	EggPkg,
	//PacmanPkg,
	RpmPkg,
	WheelPkg,
	NpmPkg,
	YarnPkg,
	PythonRequirementsPkg,
	JavaPkg,
	JenkinsPluginPkg,
	GoModulePkg,
}

func (t Type) String() string {
	if int(t) >= len(typeStr) {
		return typeStr[0]
	}
	return typeStr[t]
}
