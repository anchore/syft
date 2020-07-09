package pkg

const (
	UnknownPkg Type = iota
	//ApkPkg
	BundlerPkg
	DebPkg
	EggPkg
	//PacmanPkg
	RpmPkg
	WheelPkg
	JavaPkg
	JenkinsPluginPkg
)

type Type uint

var typeStr = []string{
	"UnknownPackage",
	//"apk",
	"bundle",
	"deb",
	"egg",
	//"pacman",
	"rpm",
	"wheel",
	"java-archive",
	"jenkins-plugin",
}

var AllPkgs = []Type{
	//ApkPkg,
	BundlerPkg,
	DebPkg,
	EggPkg,
	//PacmanPkg,
	RpmPkg,
	WheelPkg,
	JavaPkg,
	JenkinsPluginPkg,
}

func (t Type) String() string {
	if int(t) >= len(typeStr) {
		return typeStr[0]
	}
	return typeStr[t]
}
