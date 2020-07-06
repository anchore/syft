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
}

var AllPkgs = []Type{
	//ApkPkg,
	BundlerPkg,
	DebPkg,
	EggPkg,
	//PacmanPkg,
	RpmPkg,
	WheelPkg,
}

func (t Type) String() string {
	if int(t) >= len(typeStr) {
		return typeStr[0]
	}
	return typeStr[t]
}
