package handler

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

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

	timeout := time.Duration(h.config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	go func() {
		defer wg.Done()
		defer closeConns()
		if _, err := copyWithTimeout(backendConn, conn, timeout); err != nil {
			if !isIgnorableError(err) {
				zap.L().Error(fmt.Sprintf("Error copying data from client to backend: %v", err))
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer closeConns()
		if _, err := copyWithTimeout(conn, backendConn, timeout); err != nil {
			if !isIgnorableError(err) {
				zap.L().Error(fmt.Sprintf("Error copying data from backend to client: %v", err))
			}
		}
	}()

	wg.Wait()
	zap.L().Info(fmt.Sprintf("Connection closed. Remote Addr: %s, Backend: %s", conn.RemoteAddr().String(), h.config.Backend))
}

func copyWithTimeout(dst io.Writer, src io.Reader, timeout time.Duration) (written int64, err error) {
	buf := make([]byte, 32*1024)
	for {
		if conn, ok := src.(net.Conn); ok {
			if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
				return 0, err
			}
		}

		if conn, ok := dst.(net.Conn); ok {
			if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
				return 0, err
			}
		}

		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	if conn, ok := src.(net.Conn); ok {
		_ = conn.SetReadDeadline(time.Time{})
	}
	if conn, ok := dst.(net.Conn); ok {
		_ = conn.SetWriteDeadline(time.Time{})
	}
	return written, err
}

func isIgnorableError(err error) bool {
	if err == io.EOF {
		return true
	}

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	if strings.Contains(err.Error(), "connection reset by peer") ||
		strings.Contains(err.Error(), "forcibly closed by the remote host") ||
		strings.Contains(err.Error(), "use of closed network connection") {
		return true
	}
	return false
}
