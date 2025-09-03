package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/eWloYW8/TCPMux/config"
	"github.com/eWloYW8/TCPMux/logger"
	"github.com/eWloYW8/TCPMux/server"

	"go.uber.org/zap"
)

var Version = "dev-build"

func main() {
	fmt.Fprintf(os.Stderr, "TCPMux %s - A TCP traffic multiplexer written in Go\n", Version)

	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	zap.L().Info("Starting TCPMux server...", zap.String("version", Version))

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		zap.L().Fatal("failed to load config", zap.Error(err))
	}

	if err := logger.InitLogger(cfg.Logging); err != nil {
		zap.L().Fatal("failed to initialize logger", zap.Error(err))
	}
	defer zap.L().Sync()

	zap.L().Info("Logger initialized successfully")

	s, err := server.NewServer(cfg)
	if err != nil {
		zap.L().Fatal("failed to create server", zap.Error(err))
	}

	go func() {
		if err := s.Start(); err != nil {
			zap.L().Fatal("failed to start server", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	s.Stop()
	zap.L().Info("server shutdown complete.")
}
