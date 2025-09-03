package handler

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/eWloYW8/TCPMux/config"

	"go.uber.org/zap"
)

type PassthroughHandler struct {
	config *config.HandlerConfig
}

func NewPassthroughHandler(config *config.HandlerConfig) *PassthroughHandler {
	return &PassthroughHandler{config: config}
}

func (h *PassthroughHandler) Handle(conn net.Conn) {
	zap.L().Info("Handling connection with passthrough handler",
		zap.String("backend", h.config.Backend),
		zap.String("remote_addr", conn.RemoteAddr().String()))

	defer conn.Close()

	var backendConn net.Conn
	var err error

	if h.config.TLS {
		backendConn, err = tls.Dial("tcp", h.config.Backend, &tls.Config{InsecureSkipVerify: true})
	} else {
		backendConn, err = net.Dial("tcp", h.config.Backend)
	}

	if err != nil {
		zap.L().Error("Failed to connect to backend",
			zap.String("backend", h.config.Backend),
			zap.String("remote_addr", conn.RemoteAddr().String()),
			zap.Error(err))
		return
	}
	zap.L().Info("Successfully connected to backend",
		zap.String("backend", h.config.Backend),
		zap.String("remote_addr", conn.RemoteAddr().String()))

	defer backendConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(backendConn, conn); err != nil && !isIgnorableError(err) {
			zap.L().Error("Error copying data from client to backend", zap.Error(err))
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(conn, backendConn); err != nil && !isIgnorableError(err) {
			zap.L().Error("Error copying data from backend to client", zap.Error(err))
		}
	}()

	wg.Wait()
	zap.L().Info("Connection closed",
		zap.String("remote_addr", conn.RemoteAddr().String()),
		zap.String("backend", h.config.Backend))
}

// isIgnorableError checks if the error is a known one that occurs during normal shutdown.
func isIgnorableError(err error) bool {
	if err == io.EOF ||
		strings.Contains(err.Error(), "connection reset by peer") ||
		strings.Contains(err.Error(), "forcibly closed by the remote host") {
		return true
	}
	return false
}
