package logger

import (
	"fmt"
	"io"
	"log"

	"github.com/hashicorp/go-hclog"
	"github.com/sirupsen/logrus"
)

// integrity check
var _ hclog.Logger = &LogrusHCLogAdapter{}

var levels = map[hclog.Level]logrus.Level{
	hclog.NoLevel: logrus.PanicLevel,
	hclog.Error:   logrus.ErrorLevel,
	hclog.Warn:    logrus.WarnLevel,
	hclog.Info:    logrus.InfoLevel,
	hclog.Debug:   logrus.DebugLevel,
	hclog.Trace:   logrus.TraceLevel,
}

// LogrusHCLogAdapter is used to adapt a logrus logger object to the hclog.Logger interface for syft plugins.
type LogrusHCLogAdapter struct {
	logger *logrus.Logger
	entry  *logrus.Entry
}

func NewLogrusHCLogAdapter(logger *logrus.Logger, fields map[string]interface{}) *LogrusHCLogAdapter {
	if fields != nil {
		return &LogrusHCLogAdapter{
			logger: logger,
			entry:  logger.WithFields(fields),
		}
	}
	return &LogrusHCLogAdapter{
		logger: logger,
	}
}

func (l *LogrusHCLogAdapter) log(level hclog.Level, msg string, args ...interface{}) {
	if l.entry != nil {
		l.entry.WithFields(makeArgFields(args...)).Log(levels[level], msg)
		return
	}
	l.logger.WithFields(makeArgFields(args...)).Log(levels[level], msg)
}

// Args are alternating key, val pairs
// keys must be strings
// vals can be any type, but display is implementation specific
// Emit a message and key/value pairs at a provided log level
func (l *LogrusHCLogAdapter) Log(level hclog.Level, msg string, args ...interface{}) {
	l.log(level, msg, args...)
}

// Emit a message and key/value pairs at the TRACE level
func (l *LogrusHCLogAdapter) Trace(msg string, args ...interface{}) {
	l.log(hclog.Trace, msg, args...)
}

// Emit a message and key/value pairs at the DEBUG level
func (l *LogrusHCLogAdapter) Debug(msg string, args ...interface{}) {
	l.log(hclog.Debug, msg, args...)
}

// Emit a message and key/value pairs at the INFO level
func (l *LogrusHCLogAdapter) Info(msg string, args ...interface{}) {
	l.log(hclog.Info, msg, args...)
}

// Emit a message and key/value pairs at the WARN level
func (l *LogrusHCLogAdapter) Warn(msg string, args ...interface{}) {
	l.log(hclog.Warn, msg, args...)
}

// Emit a message and key/value pairs at the ERROR level
func (l *LogrusHCLogAdapter) Error(msg string, args ...interface{}) {
	l.log(hclog.Error, msg, args...)
}

// Indicate if TRACE logs would be emitted. This and the other Is* guards
// are used to elide expensive logging code based on the current level.
func (l *LogrusHCLogAdapter) IsTrace() bool {
	return l.logger.Level <= logrus.TraceLevel
}

// Indicate if DEBUG logs would be emitted. This and the other Is* guards
// are used to elide expensive logging code based on the current level.
func (l *LogrusHCLogAdapter) IsDebug() bool {
	return l.logger.Level <= logrus.DebugLevel
}

// Indicate if INFO logs would be emitted. This and the other Is* guards
// are used to elide expensive logging code based on the current level.
func (l *LogrusHCLogAdapter) IsInfo() bool {
	return l.logger.Level <= logrus.InfoLevel
}

// Indicate if WARN logs would be emitted. This and the other Is* guards
// are used to elide expensive logging code based on the current level.
func (l *LogrusHCLogAdapter) IsWarn() bool {
	return l.logger.Level <= logrus.WarnLevel
}

// Indicate if ERROR logs would be emitted. This and the other Is* guards
// are used to elide expensive logging code based on the current level.
func (l *LogrusHCLogAdapter) IsError() bool {
	return l.logger.Level <= logrus.ErrorLevel
}

// ImpliedArgs returns With key/value pairs
func (l *LogrusHCLogAdapter) ImpliedArgs() []interface{} {
	// TODO: not implemented
	return nil
}

// Creates a sublogger that will always have the given key/value pairs
func (l *LogrusHCLogAdapter) With(args ...interface{}) hclog.Logger {
	l.entry = l.logger.WithFields(makeArgFields(args...))
	return l
}

// Returns the Name of the logger
func (l *LogrusHCLogAdapter) Name() string {
	// TODO: not implemented
	return ""
}

// Create a logger that will prepend the name string on the front of all messages.
// If the logger already has a name, the new value will be appended to the current
// name. That way, a major subsystem can use this to decorate all it's own logs
// without losing context.
func (l *LogrusHCLogAdapter) Named(name string) hclog.Logger {
	return NewLogrusHCLogAdapter(l.logger, logrus.Fields{"name": name})
}

// Create a logger that will prepend the name string on the front of all messages.
// This sets the name of the logger to the value directly, unlike Named which honor
// the current name as well.
func (l *LogrusHCLogAdapter) ResetNamed(name string) hclog.Logger {
	return NewLogrusHCLogAdapter(l.logger, logrus.Fields{"name": name})
}

// Updates the level. This should affect all sub-loggers as well. If an
// implementation cannot update the level on the fly, it should no-op.
func (l *LogrusHCLogAdapter) SetLevel(level hclog.Level) {
	l.logger.SetLevel(levels[level])
}

// Return a value that conforms to the stdlib log.Logger interface
func (l *LogrusHCLogAdapter) StandardLogger(opts *hclog.StandardLoggerOptions) *log.Logger {
	return log.New(l.StandardWriter(opts), "", log.LstdFlags)
}

// Return a value that conforms to io.Writer, which can be passed into log.SetOutput()
func (l *LogrusHCLogAdapter) StandardWriter(opts *hclog.StandardLoggerOptions) io.Writer {
	return &HCLogStdlogAdapter{
		log:         l,
		inferLevels: opts.InferLevels,
		forceLevel:  opts.ForceLevel,
	}
}

func makeArgFields(args ...interface{}) logrus.Fields {
	if len(args)%2 != 0 {
		panic(fmt.Errorf("odd number of logger key-value pairs (%d): %+v", len(args), args))
	}

	var key string
	var fields = make(logrus.Fields)
	for i, arg := range args {
		if i%2 == 0 {
			key = arg.(string)
		} else {
			fields[key] = arg
		}
	}
	return fields
}
