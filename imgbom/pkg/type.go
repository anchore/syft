package pkg

const (
	UnknownPkg Type = iota
	ApkPkg
	BundlerPkg
	DebPkg
	PacmanPkg
	RpmPkg
)

type Type uint

var typeStr = []string{
	"UnknownPackage",
	"apk",
	"bundler",
	"deb",
	"pacman",
	"rpm",
}

var AllPkgs = []Type{
	ApkPkg,
	BundlerPkg,
	DebPkg,
	PacmanPkg,
	RpmPkg,
}

func (t Type) String() string {
	if int(t) >= len(typeStr) {
		return typeStr[0]
	}
	return typeStr[t]
}
