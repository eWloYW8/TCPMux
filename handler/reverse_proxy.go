package handler

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"crypto/tls"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type ReverseProxyHandlerConfig struct {
	Backend  string `yaml:"backend"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type ReverseProxyHandler struct {
	config *ReverseProxyHandlerConfig
	proxy  *httputil.ReverseProxy
}

func init() {
	Register("reverse_proxy", newReverseProxyHandler)
}

func newReverseProxyHandler(parameter yaml.Node) (Handler, error) {
	cfg := &ReverseProxyHandlerConfig{}
	if err := parameter.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode reverse_proxy handler config: %v", err)
	}

	backendURL, err := url.Parse(cfg.Backend)
	if err != nil {
		return nil, fmt.Errorf("invalid backend URL '%s': %v", cfg.Backend, err)
	}

	h := &ReverseProxyHandler{
		config: cfg,
	}

	h.proxy = httputil.NewSingleHostReverseProxy(backendURL)

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2: false,
	}
	if backendURL.Scheme == "https" {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         backendURL.Hostname(),
		}
	}
	h.proxy.Transport = transport

	h.proxy.Director = func(req *http.Request) {
		req.URL.Scheme = backendURL.Scheme
		req.URL.Host = backendURL.Host
		req.Host = backendURL.Host
	}

	return h, nil
}

func (h *ReverseProxyHandler) Handle(conn net.Conn) {
	zap.L().Info("Handling connection with reverse_proxy handler",
		zap.String("backend", h.config.Backend),
		zap.String("remote_addr", conn.RemoteAddr().String()))

	defer conn.Close()

	reader := bufio.NewReader(conn)

	for {
		// Set a read deadline for keep-alive connections
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		req, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded) {
				zap.L().Debug("Client connection closed gracefully or timed out.", zap.String("remote_addr", conn.RemoteAddr().String()))
			} else if !strings.Contains(err.Error(), "client disconnected") {
				zap.L().Error("Failed to read HTTP request", zap.Error(err), zap.String("remote_addr", conn.RemoteAddr().String()))
			}
			return
		}

		if h.config.Username != "" || h.config.Password != "" {
			user, pass, ok := req.BasicAuth()
			if !ok || user != h.config.Username || pass != h.config.Password {
				h.sendUnauthorized(conn)
				zap.L().Warn("Basic authentication failed for connection",
					zap.String("remote_addr", conn.RemoteAddr().String()))
				return
			}
		}

		if h.isWebSocketUpgrade(req) {
			h.handleWebSocket(conn, req)
			return
		}

		rw := NewHTTPResponseWriter(conn)
		h.proxy.ServeHTTP(rw, req)

		if strings.ToLower(req.Header.Get("Connection")) == "close" || strings.ToLower(rw.Header().Get("Connection")) == "close" {
			zap.L().Debug("Connection: close header detected, closing connection.", zap.String("remote_addr", conn.RemoteAddr().String()))
			return
		}

		// Flush any pending data before waiting for the next request
		if err := rw.w.Flush(); err != nil {
			zap.L().Error("Failed to flush writer after request.", zap.Error(err))
			return
		}
	}
}

func (h *ReverseProxyHandler) isWebSocketUpgrade(req *http.Request) bool {
	return strings.ToLower(req.Header.Get("Connection")) == "upgrade" &&
		strings.ToLower(req.Header.Get("Upgrade")) == "websocket"
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func (h *ReverseProxyHandler) handleWebSocket(conn net.Conn, req *http.Request) {
	backendURL, _ := url.Parse(h.config.Backend)
	backendWsURL := "ws" + strings.TrimPrefix(h.config.Backend, "http") + req.URL.Path
	if req.URL.RawQuery != "" {
		backendWsURL += "?" + req.URL.RawQuery
	}

	zap.L().Info("Upgrading connection to WebSocket",
		zap.String("backend", backendWsURL),
		zap.String("remote_addr", conn.RemoteAddr().String()))

	rw := NewHTTPResponseWriter(conn)

	clientWs, err := upgrader.Upgrade(rw, req, nil)
	if err != nil {
		zap.L().Error("Failed to upgrade client to WebSocket", zap.Error(err))
		return
	}

	defer clientWs.Close()

	var tlsConfig *tls.Config
	if backendURL.Scheme == "https" {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         backendURL.Hostname(),
		}
	}

	backendHeaders := make(http.Header)

	ignoredHeaders := map[string]struct{}{
		"Connection":               {},
		"Upgrade":                  {},
		"Sec-Websocket-Key":        {},
		"Sec-Websocket-Version":    {},
		"Sec-Websocket-Protocol":   {},
		"Sec-Websocket-Extensions": {},
	}

	for k, v := range req.Header {
		if _, ok := ignoredHeaders[http.CanonicalHeaderKey(k)]; !ok {
			backendHeaders[k] = v
		}
	}

	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
		Subprotocols:     websocket.Subprotocols(req),
		TLSClientConfig:  tlsConfig,
	}

	backendWs, resp, err := dialer.Dial(backendWsURL, backendHeaders)
	if err != nil {
		if resp != nil {
			zap.L().Error("Failed to dial backend WebSocket",
				zap.Error(err),
				zap.Int("status_code", resp.StatusCode),
				zap.String("backend_url", backendWsURL))
		} else {
			zap.L().Error("Failed to dial backend WebSocket",
				zap.Error(err),
				zap.String("backend_url", backendWsURL))
		}
		return
	}

	defer backendWs.Close()

	errCh := make(chan error, 2)
	go func() { errCh <- h.copyWebSocket(clientWs, backendWs) }()
	go func() { errCh <- h.copyWebSocket(backendWs, clientWs) }()

	<-errCh
	<-errCh

	zap.L().Info("WebSocket connections closed gracefully.",
		zap.String("remote_addr", conn.RemoteAddr().String()),
		zap.String("backend", h.config.Backend))
}

func (h *ReverseProxyHandler) copyWebSocket(dst, src *websocket.Conn) error {
	for {
		messageType, p, err := src.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) || errors.Is(err, io.EOF) {
				dst.WriteControl(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "normal closure"),
					time.Now().Add(time.Second))
				zap.L().Debug("WebSocket connection closed normally.", zap.Error(err))
				return nil
			}

			zap.L().Error("WebSocket read error.", zap.Error(err))
			return err
		}

		if err := dst.WriteMessage(messageType, p); err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) || errors.Is(err, io.EOF) {
				zap.L().Debug("WebSocket write connection closed normally.", zap.Error(err))
				return nil
			}

			zap.L().Error("WebSocket write error.", zap.Error(err))
			return err
		}
	}
}

func (h *ReverseProxyHandler) sendUnauthorized(conn net.Conn) {
	resp := &http.Response{
		Status:     "401 Unauthorized",
		StatusCode: http.StatusUnauthorized,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"WWW-Authenticate": []string{`Basic realm="Restricted"`},
		},
		Body:          io.NopCloser(strings.NewReader("401 Unauthorized\n")),
		ContentLength: int64(len("401 Unauthorized\n")),
	}

	resp.Write(conn)
	conn.Close()
}

type HTTPResponseWriter struct {
	conn       net.Conn
	header     http.Header
	statusCode int
	written    bool
	w          *bufio.Writer
}

func NewHTTPResponseWriter(conn net.Conn) *HTTPResponseWriter {
	return &HTTPResponseWriter{
		conn:   conn,
		header: make(http.Header),
		w:      bufio.NewWriter(conn),
	}
}

func (w *HTTPResponseWriter) Header() http.Header {
	return w.header
}

func (w *HTTPResponseWriter) Write(data []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.w.Write(data)
}

func (w *HTTPResponseWriter) WriteHeader(statusCode int) {
	if w.written {
		zap.L().Warn("Ignoring multiple calls to WriteHeader", zap.Int("status_code", statusCode))
		return
	}
	w.statusCode = statusCode

	statusLine := fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode))
	w.w.Write([]byte(statusLine))

	w.header.Write(w.w)

	w.w.Write([]byte("\r\n"))

	w.written = true
}

func (w *HTTPResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.written {
		return nil, nil, errors.New("cannot hijack a connection after the header has been written")
	}
	if err := w.w.Flush(); err != nil {
		return nil, nil, fmt.Errorf("failed to flush writer: %v", err)
	}
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), w.w), nil
}
