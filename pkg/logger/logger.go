package logger

import (
	"os"

	"github.com/eWloYW8/TCPMux/pkg/config"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func InitLogger(cfg config.LoggingConfig) error {
	logLevel := zap.NewAtomicLevel()
	if err := logLevel.UnmarshalText([]byte(cfg.Level)); err != nil {
		return err
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	cores := []zapcore.Core{}

	if cfg.Stderr {
		cores = append(cores, zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
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
			zapcore.NewJSONEncoder(encoderConfig),
			fileSyncer,
			logLevel,
		))
	}

	logger := zap.New(zapcore.NewTee(cores...), zap.AddCaller())
	zap.ReplaceGlobals(logger)

	return nil
}
