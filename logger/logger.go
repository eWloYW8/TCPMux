// FILE: logger/logger.go
package logger

import (
	"os"

	"github.com/eWloYW8/TCPMux/config"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func InitLogger(cfg config.LoggingConfig) error {
	logLevel := zap.NewAtomicLevel()
	if err := logLevel.UnmarshalText([]byte(cfg.Level)); err != nil {
		return err
	}

	consoleEncoderConfig := zap.NewDevelopmentEncoderConfig()
	consoleEncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	consoleEncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	consoleEncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder

	jsonEncoderConfig := zap.NewProductionEncoderConfig()
	jsonEncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	var encoder zapcore.Encoder
	if cfg.Format == "json" {
		encoder = zapcore.NewJSONEncoder(jsonEncoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(consoleEncoderConfig)
	}

	cores := []zapcore.Core{}

	if cfg.Stderr {
		cores = append(cores, zapcore.NewCore(
			encoder,
			zapcore.AddSync(zapcore.Lock(zapcore.NewMultiWriteSyncer(zapcore.AddSync(os.Stderr)))),
			logLevel,
		))
	}

	if cfg.File != "" {
		fileSyncer, _, err := zap.Open(cfg.File)
		if err != nil {
			return err
		}
		cores = append(cores, zapcore.NewCore(
			encoder,
			fileSyncer,
			logLevel,
		))
	}

	logger := zap.New(zapcore.NewTee(cores...), zap.AddCaller())
	zap.ReplaceGlobals(logger)

	return nil
}
