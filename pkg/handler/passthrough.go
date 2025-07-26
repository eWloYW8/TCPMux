package handler

import (
	"crypto/tls"
	"io"
	"net"
	"sync"

	"github.com/eWloYW8/TCPMux/pkg/config"

	"go.uber.org/zap"
)

type PassthroughHandler struct {
	config *config.HandlerConfig
}

func NewPassthroughHandler(config *config.HandlerConfig) *PassthroughHandler {
	return &PassthroughHandler{config: config}
}

func (h *PassthroughHandler) Handle(conn net.Conn) {
	defer conn.Close()

	var backendConn net.Conn
	var err error

	if h.config.TLS {
		backendConn, err = tls.Dial("tcp", h.config.Backend, &tls.Config{InsecureSkipVerify: true})
	} else {
		backendConn, err = net.Dial("tcp", h.config.Backend)
	}

	if err != nil {
		zap.L().Error("failed to connect to backend", zap.String("backend", h.config.Backend), zap.Error(err))
		return
	}
	defer backendConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(backendConn, conn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, backendConn)
	}()

	wg.Wait()
}
