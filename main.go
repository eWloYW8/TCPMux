package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eWloYW8/TCPMux/config"
	"github.com/eWloYW8/TCPMux/controller"
	"github.com/eWloYW8/TCPMux/logger"
	"github.com/eWloYW8/TCPMux/server"

	"go.uber.org/zap"
)

var Version = "dev-build"

func main() {
	fmt.Fprintf(os.Stderr, "TCPMux %s - A TCP traffic multiplexer written in Go\n", Version)

	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	fmt.Fprintf(os.Stderr, "Starting TCPMux server...\n")

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	if err := logger.InitLogger(cfg.Logging); err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
	}
	defer zap.L().Sync()

	zap.L().Info("Logger initialized successfully")

	s, err := server.NewServer(cfg)
	if err != nil {
		zap.L().Fatal("failed to create server", zap.Error(err))
	}

	var ctrl *controller.Controller
	if cfg.Controller.Enabled {
		ctrl = controller.NewController(s, &cfg.Controller)
		go func() {
			ctrl.Start()
		}()
	}

	go func() {
		if err := s.Start(); err != nil {
			zap.L().Fatal("failed to start server", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	secondQuit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		zap.L().Info("First shutdown signal received. Starting graceful shutdown...")
		signal.Notify(secondQuit, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			<-secondQuit
			zap.L().Warn("Second shutdown signal received! Forcing exit.")
			os.Exit(1)
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.Stop()

		if ctrl != nil {
			ctrl.Stop(ctx)
		}

		zap.L().Info("Server shutdown complete. Exiting.")
		os.Exit(0)
	}()
	select {}

}
