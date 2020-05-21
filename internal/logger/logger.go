package logger

type Logger interface {
	Errorf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Info(args ...interface{})
	Debugf(format string, args ...interface{})
	Debug(args ...interface{})
	// WithFields(map[string]interface{}) Logger
}

func Errorf(format string, args ...interface{}) {
	Log.Errorf(format, args...)
}

func Infof(format string, args ...interface{}) {
	Log.Infof(format, args...)
}

func Info(args ...interface{}) {
	Log.Info(args...)
}

func Debugf(format string, args ...interface{}) {
	Log.Debugf(format, args...)
}

func Debug(args ...interface{}) {
	Log.Debug(args...)
}

// func WithFields(fields map[string]interface{}) Logger {
// 	return Log.WithFields(fields)
// }
