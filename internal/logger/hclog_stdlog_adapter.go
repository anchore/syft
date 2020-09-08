package logger

import (
	"bytes"
	"strings"

	"github.com/hashicorp/go-hclog"
)

// Source: https://github.com/hashicorp/go-hclog/blob/master/stdlog.go (MIT License)

// Provides a io.Writer to shim the data out of *log.Logger
// and back into our Logger. This is basically the only way to
// build upon *log.Logger.
type HCLogStdlogAdapter struct {
	log         hclog.Logger
	inferLevels bool
	forceLevel  hclog.Level
}

// Take the data, infer the levels if configured, and send it through
// a regular Logger.
func (s *HCLogStdlogAdapter) Write(data []byte) (int, error) {
	str := string(bytes.TrimRight(data, " \t\n"))

	if s.forceLevel != hclog.NoLevel {
		// Use pickLevel to strip log levels included in the line since we are
		// forcing the level
		_, str := s.pickLevel(str)

		// Log at the forced level
		s.dispatch(str, s.forceLevel)
	} else if s.inferLevels {
		level, str := s.pickLevel(str)
		s.dispatch(str, level)
	} else {
		s.log.Info(str)
	}

	return len(data), nil
}

func (s *HCLogStdlogAdapter) dispatch(str string, level hclog.Level) {
	switch level {
	case hclog.Trace:
		s.log.Trace(str)
	case hclog.Debug:
		s.log.Debug(str)
	case hclog.Info:
		s.log.Info(str)
	case hclog.Warn:
		s.log.Warn(str)
	case hclog.Error:
		s.log.Error(str)
	default:
		s.log.Info(str)
	}
}

// Detect, based on conventions, what log level this is.
func (s *HCLogStdlogAdapter) pickLevel(str string) (hclog.Level, string) {
	switch {
	case strings.HasPrefix(str, "[DEBUG]"):
		return hclog.Debug, strings.TrimSpace(str[7:])
	case strings.HasPrefix(str, "[TRACE]"):
		return hclog.Trace, strings.TrimSpace(str[7:])
	case strings.HasPrefix(str, "[INFO]"):
		return hclog.Info, strings.TrimSpace(str[6:])
	case strings.HasPrefix(str, "[WARN]"):
		return hclog.Warn, strings.TrimSpace(str[7:])
	case strings.HasPrefix(str, "[ERROR]"):
		return hclog.Error, strings.TrimSpace(str[7:])
	case strings.HasPrefix(str, "[ERR]"):
		return hclog.Error, strings.TrimSpace(str[5:])
	default:
		return hclog.Info, str
	}
}
