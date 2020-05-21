package logger

var Log Logger

func init() {
	SetLogger(&nopLogger{})
}

func SetLogger(logger Logger) {
	Log = logger
}
