package logger

import (
	"os"

	"github.com/anchore/imgbom/imgbom/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type LogConfig struct {
	EnableConsole bool
	EnableFile    bool
	FormatAsJSON  bool
	Level         zapcore.Level
	FileLocation  string
}

type ZapLogger struct {
	sugaredLogger *zap.SugaredLogger
}

func NewZapLogger(config LogConfig) *ZapLogger {
	cores := []zapcore.Core{}

	if config.EnableConsole {
		// note: the report should go to stdout, all logs should go to stderr
		writer := zapcore.Lock(os.Stderr)
		core := zapcore.NewCore(getConsoleEncoder(config), writer, config.Level)
		cores = append(cores, core)
	}

	if config.EnableFile {
		writer := zapcore.AddSync(getLogWriter(config.FileLocation))
		core := zapcore.NewCore(getFileEncoder(config), writer, config.Level)
		cores = append(cores, core)
	}

	combinedCore := zapcore.NewTee(cores...)

	// AddCallerSkip skips 2 number of callers, this is important else the file that gets
	// logged will always be the wrapped file (In our case logger.go)
	logger := zap.New(combinedCore,
		zap.AddCallerSkip(2),
		zap.AddCaller(),
	).Sugar()

	return &ZapLogger{
		sugaredLogger: logger,
	}
}

func getConsoleEncoder(config LogConfig) zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	if config.FormatAsJSON {
		return zapcore.NewJSONEncoder(encoderConfig)
	}
	encoderConfig.EncodeTime = nil
	encoderConfig.EncodeCaller = nil
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	return zapcore.NewConsoleEncoder(encoderConfig)
}

func getFileEncoder(config LogConfig) zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	if config.FormatAsJSON {
		return zapcore.NewJSONEncoder(encoderConfig)
	}
	return zapcore.NewConsoleEncoder(encoderConfig)
}

func getLogWriter(location string) zapcore.WriteSyncer {
	file, _ := os.Create(location)
	return zapcore.AddSync(file)
}

func (l *ZapLogger) Debugf(format string, args ...interface{}) {
	l.sugaredLogger.Debugf(format, args...)
}

func (l *ZapLogger) Infof(format string, args ...interface{}) {
	l.sugaredLogger.Infof(format, args...)
}

func (l *ZapLogger) Debug(args ...interface{}) {
	l.sugaredLogger.Debug(args...)
}

func (l *ZapLogger) Info(args ...interface{}) {
	l.sugaredLogger.Info(args...)
}

func (l *ZapLogger) Errorf(format string, args ...interface{}) {
	l.sugaredLogger.Errorf(format, args...)
}

func (l *ZapLogger) WithFields(fields map[string]interface{}) logger.Logger {
	var f = make([]interface{}, 0)
	for k, v := range fields {
		f = append(f, k)
		f = append(f, v)
	}
	newLogger := l.sugaredLogger.With(f...)
	return &ZapLogger{newLogger}
}
