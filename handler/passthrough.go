package handler

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"

	"github.com/eWloYW8/TCPMux/config"
	"go.uber.org/zap"
)

func init() {
	Register("passthrough", newPassthroughHandler)
}

type PassthroughHandler struct {
	config *config.HandlerConfig
}

func newPassthroughHandler(config *config.HandlerConfig) (Handler, error) {
	return NewPassthroughHandler(config), nil
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

	if h.config.TLS != nil && h.config.TLS.Enabled {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: h.config.TLS.InsecureSkipVerify,
		}

		if tlsConn, ok := conn.(*tls.Conn); ok {
			connState := tlsConn.ConnectionState()
			if h.config.TLS.SNI != "" {
				tlsConfig.ServerName = h.config.TLS.SNI
			} else if connState.ServerName != "" {
				tlsConfig.ServerName = connState.ServerName
			}

			if len(h.config.TLS.ALPN) > 0 {
				tlsConfig.NextProtos = h.config.TLS.ALPN
			} else if connState.NegotiatedProtocol != "" {
				tlsConfig.NextProtos = []string{connState.NegotiatedProtocol}
			}
		} else if h.config.TLS.SNI != "" {
			tlsConfig.ServerName = h.config.TLS.SNI
		}

		zap.L().Debug("Connecting to backend with TLS",
			zap.String("backend", h.config.Backend),
			zap.String("sni", tlsConfig.ServerName),
			zap.Strings("alpn", tlsConfig.NextProtos))

		backendConn, err = tls.Dial("tcp", h.config.Backend, tlsConfig)
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

	closeOnce := sync.Once{}
	closeConns := func() {
		closeOnce.Do(func() {
			conn.Close()
			backendConn.Close()
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer closeConns()
		if _, err := io.Copy(backendConn, conn); err != nil {
			if !isIgnorableError(err) {
				zap.L().Error("Error copying data from client to backend", zap.Error(err))
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer closeConns()
		if _, err := io.Copy(conn, backendConn); err != nil {
			if !isIgnorableError(err) {
				zap.L().Error("Error copying data from backend to client", zap.Error(err))
			}
		}
	}()

	wg.Wait()
	zap.L().Info("Connection closed",
		zap.String("remote_addr", conn.RemoteAddr().String()),
		zap.String("backend", h.config.Backend))
}

func isIgnorableError(err error) bool {
	if err == nil {
		return true
	}

	if errors.Is(err, io.EOF) {
		return true
	}

	if errors.Is(err, syscall.EPIPE) {
		return true
	}

	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}

	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		return true
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if strings.Contains(opErr.Err.Error(), "use of closed network connection") ||
			strings.Contains(opErr.Err.Error(), "closed by the remote host") {
			return true
		}
	}

	return false
}
