package logger

import (
	"io"
	"log"

	"github.com/anchore/syft/syft/logger"

	"github.com/hashicorp/go-hclog"
)

// integrity check
var _ hclog.Logger = &LoggerHCLogAdapter{}

// LoggerHCLogAdapter is used to (partially) adapt a syft logger.Logger object to the hclog.Logger interface for syft plugins.
// Note: this does not implement all functionality required by the hclog.Logger.
type LoggerHCLogAdapter struct {
	Logger logger.Logger
}

func NewLoggerHCLogAdapter(logger logger.Logger) *LoggerHCLogAdapter {
	return &LoggerHCLogAdapter{
		Logger: logger,
	}
}

// Args are alternating key, val pairs
// keys must be strings
// vals can be any type, but display is implementation specific
// Emit a message and key/value pairs at a provided log level
func (l *LoggerHCLogAdapter) Log(level hclog.Level, msg string, args ...interface{}) {
	l.Logger.Info(append([]interface{}{msg}, args...)...)
}

// Emit a message and key/value pairs at the TRACE level
func (l *LoggerHCLogAdapter) Trace(msg string, args ...interface{}) {
	l.Logger.Debug(append([]interface{}{msg}, args...)...)
}

// Emit a message and key/value pairs at the DEBUG level
func (l *LoggerHCLogAdapter) Debug(msg string, args ...interface{}) {
	l.Logger.Debug(append([]interface{}{msg}, args...)...)
}

// Emit a message and key/value pairs at the INFO level
func (l *LoggerHCLogAdapter) Info(msg string, args ...interface{}) {
	l.Logger.Info(append([]interface{}{msg}, args...)...)
}

// Emit a message and key/value pairs at the WARN level
func (l *LoggerHCLogAdapter) Warn(msg string, args ...interface{}) {
	l.Logger.Error(append([]interface{}{msg}, args...)...)
}

// Emit a message and key/value pairs at the ERROR level
func (l *LoggerHCLogAdapter) Error(msg string, args ...interface{}) {
	l.Logger.Error(append([]interface{}{msg}, args...)...)
}

// Indicate if TRACE logs would be emitted. This and the other Is* guards
// are used to elide expensive logging code based on the current level.
func (l *LoggerHCLogAdapter) IsTrace() bool {
	// TODO: not implemented
	return true
}

// Indicate if DEBUG logs would be emitted. This and the other Is* guards
// are used to elide expensive logging code based on the current level.
func (l *LoggerHCLogAdapter) IsDebug() bool {
	// TODO: not implemented
	return true
}

// Indicate if INFO logs would be emitted. This and the other Is* guards
// are used to elide expensive logging code based on the current level.
func (l *LoggerHCLogAdapter) IsInfo() bool {
	// TODO: not implemented
	return true
}

// Indicate if WARN logs would be emitted. This and the other Is* guards
// are used to elide expensive logging code based on the current level.
func (l *LoggerHCLogAdapter) IsWarn() bool {
	// TODO: not implemented
	return true
}

// Indicate if ERROR logs would be emitted. This and the other Is* guards
// are used to elide expensive logging code based on the current level.
func (l *LoggerHCLogAdapter) IsError() bool {
	// TODO: not implemented
	return true
}

// ImpliedArgs returns With key/value pairs
func (l *LoggerHCLogAdapter) ImpliedArgs() []interface{} {
	// TODO: not implemented
	return nil
}

// Creates a sublogger that will always have the given key/value pairs
func (l *LoggerHCLogAdapter) With(args ...interface{}) hclog.Logger {
	// TODO: not implemented
	return l
}

// Returns the Name of the logger
func (l *LoggerHCLogAdapter) Name() string {
	// TODO: not implemented
	return ""
}

// Create a logger that will prepend the name string on the front of all messages.
// If the logger already has a name, the new value will be appended to the current
// name. That way, a major subsystem can use this to decorate all it's own logs
// without losing context.
func (l *LoggerHCLogAdapter) Named(name string) hclog.Logger {
	// TODO: not implemented
	return l
}

// Create a logger that will prepend the name string on the front of all messages.
// This sets the name of the logger to the value directly, unlike Named which honor
// the current name as well.
func (l *LoggerHCLogAdapter) ResetNamed(name string) hclog.Logger {
	// TODO: not implemented
	return l
}

// Updates the level. This should affect all sub-loggers as well. If an
// implementation cannot update the level on the fly, it should no-op.
func (l *LoggerHCLogAdapter) SetLevel(level hclog.Level) {
	// TODO: not implemented
}

// Return a value that conforms to the stdlib log.Logger interface
func (l *LoggerHCLogAdapter) StandardLogger(opts *hclog.StandardLoggerOptions) *log.Logger {
	return log.New(l.StandardWriter(opts), "", log.LstdFlags)
}

// Return a value that conforms to io.Writer, which can be passed into log.SetOutput()
func (l *LoggerHCLogAdapter) StandardWriter(opts *hclog.StandardLoggerOptions) io.Writer {
	return &HCLogStdlogAdapter{
		log:         l,
		inferLevels: opts.InferLevels,
		forceLevel:  opts.ForceLevel,
	}
}
