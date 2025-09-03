package handler

import (
	"crypto/tls"
	"fmt"
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
	zap.L().Info(fmt.Sprintf("Handling connection with passthrough handler. Backend: %s, Remote Addr: %s", h.config.Backend, conn.RemoteAddr().String()))

	defer conn.Close()

	var backendConn net.Conn
	var err error

	if h.config.TLS != nil && h.config.TLS.Enabled {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: h.config.TLS.InsecureSkipVerify,
		}

		var clientSNI string
		var clientALPN string
		if tlsConn, ok := conn.(*tls.Conn); ok {
			connState := tlsConn.ConnectionState()
			clientSNI = connState.ServerName
			clientALPN = connState.NegotiatedProtocol
		}

		if h.config.TLS.SNI != "" {
			tlsConfig.ServerName = h.config.TLS.SNI
		} else if clientSNI != "" {
			tlsConfig.ServerName = clientSNI
		}

		if len(h.config.TLS.ALPN) > 0 {
			tlsConfig.NextProtos = h.config.TLS.ALPN
		} else if clientALPN != "" {
			tlsConfig.NextProtos = []string{clientALPN}
		}

		zap.L().Debug(fmt.Sprintf("Connecting to backend with TLS. Backend: %s, SNI: %s, ALPN: %v", h.config.Backend, tlsConfig.ServerName, tlsConfig.NextProtos))

		backendConn, err = tls.Dial("tcp", h.config.Backend, tlsConfig)
	} else {
		backendConn, err = net.Dial("tcp", h.config.Backend)
	}

	if err != nil {
		zap.L().Error(fmt.Sprintf("Failed to connect to backend. Backend: %s, Remote Addr: %s, Error: %v", h.config.Backend, conn.RemoteAddr().String(), err))
		return
	}
	zap.L().Info(fmt.Sprintf("Successfully connected to backend. Backend: %s, Remote Addr: %s", h.config.Backend, conn.RemoteAddr().String()))

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
				zap.L().Error(fmt.Sprintf("Error copying data from client to backend: %v", err))
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer closeConns()
		if _, err := io.Copy(conn, backendConn); err != nil {
			if !isIgnorableError(err) {
				zap.L().Error(fmt.Sprintf("Error copying data from backend to client: %v", err))
			}
		}
	}()

	wg.Wait()
	zap.L().Info(fmt.Sprintf("Connection closed. Remote Addr: %s, Backend: %s", conn.RemoteAddr().String(), h.config.Backend))
}

func isIgnorableError(err error) bool {
	if err == io.EOF {
		return true
	}

	if strings.Contains(err.Error(), "connection reset by peer") ||
		strings.Contains(err.Error(), "forcibly closed by the remote host") ||
		strings.Contains(err.Error(), "use of closed network connection") {
		return true
	}
	return false
}
