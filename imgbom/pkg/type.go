package pkg

const (
	UnknownPkg Type = iota
	ApkPkg
	DebPkg
	JavaPkg
	JavaScriptPkg
	PacmanPkg
	PythonPkg
	RpmPkg
	RubyPkg
)

type Type uint

var typeStr = []string{
	"UnknownPackage",
	"apk",
	"deb",
	"java",
	"node",
	"pacman",
	"python",
	"rpm",
	"ruby",
}

func (t Type) String() string {
	if int(t) >= len(typeStr) {
		return typeStr[0]
	}
	return typeStr[t]
}
