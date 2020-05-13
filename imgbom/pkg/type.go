package pkg

const (
	UnknownPkg uint = iota
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