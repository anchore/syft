/*
Defines the logging interface which is used throughout the syft library.
*/
package logger

type Logger interface {
	Errorf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Info(args ...interface{})
	Debugf(format string, args ...interface{})
	Debug(args ...interface{})
}
