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

	// 使用开发环境配置，它更具可读性并支持颜色
	encoderConfig := zap.NewDevelopmentEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder        // 保持时间戳为 ISO 8601
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder // 启用彩色日志级别

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
			zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
			fileSyncer,
			logLevel,
		))
	}

	logger := zap.New(zapcore.NewTee(cores...), zap.AddCaller())
	zap.ReplaceGlobals(logger)

	return nil
}
