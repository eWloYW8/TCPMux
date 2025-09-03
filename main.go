package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/eWloYW8/TCPMux/config"
	"github.com/eWloYW8/TCPMux/logger"
	"github.com/eWloYW8/TCPMux/server"

	"go.uber.org/zap"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	if err := logger.InitLogger(cfg.Logging); err != nil {
		log.Fatalf("failed to initialize logger: %v", err)
	}
	defer zap.L().Sync()

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

	zap.L().Info("shutting down server...")
	s.Stop()
}
