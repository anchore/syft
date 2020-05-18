package pkg

const (
	UnknownPkg Type = iota
	ApkPkg
	DebPkg
	JavaPkg
	NodePkg
	PacmanPkg
	PythonPkg
	RpmPkg
	RubyPkg
)

type Type uint

// TODO: stringer...
