package handler

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"crypto/tls"

	"github.com/eWloYW8/TCPMux/transport"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type ReverseProxyHandlerConfig struct {
	Backend            string `yaml:"backend"`
	Username           string `yaml:"username"`
	Password           string `yaml:"password"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

type ReverseProxyHandler struct {
	config     *ReverseProxyHandlerConfig
	wsProxy    *websocketProxy
	httpClient *http.Client
	backendURL *url.URL
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
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
		config:     cfg,
		backendURL: backendURL,
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	if backendURL.Scheme == "https" || backendURL.Scheme == "wss" {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			ServerName:         backendURL.Hostname(),
		}
	}

	h.httpClient = &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	h.wsProxy = newWebsocketProxy(backendURL, cfg.InsecureSkipVerify)

	return h, nil
}

func (h *ReverseProxyHandler) Handle(conn *transport.ClientConnection) {
	logger := conn.GetLogger()
	logger.Info("Handling connection with reverse_proxy handler",
		zap.String("backend", h.config.Backend))

	defer conn.Close()

	reader := bufio.NewReader(conn)

	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		req, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded) {
				logger.Debug("Client connection closed gracefully or timed out.")
			} else if !strings.Contains(err.Error(), "client disconnected") {
				logger.Error("Failed to read HTTP request", zap.Error(err))
			}
			return
		}

		logger.Debug("Received HTTP request",
			zap.String("method", req.Method),
			zap.String("url", req.URL.String()))

		if h.config.Username != "" || h.config.Password != "" {
			user, pass, ok := req.BasicAuth()
			if !ok || user != h.config.Username || pass != h.config.Password {
				h.sendUnauthorized(conn)
				logger.Warn("Basic authentication failed for connection")
				return
			}
		}

		if strings.ToLower(req.Header.Get("Connection")) == "upgrade" && strings.ToLower(req.Header.Get("Upgrade")) == "websocket" {
			h.wsProxy.ServeHTTP(NewHTTPResponseWriter(conn), req, logger)
			return
		}

		h.proxyHTTPRequest(req, conn)

		if strings.ToLower(req.Header.Get("Connection")) == "close" {
			logger.Debug("Connection: close header detected, closing connection.")
			return
		}
	}
}

func (h *ReverseProxyHandler) proxyHTTPRequest(req *http.Request, conn *transport.ClientConnection) {
	logger := conn.GetLogger()

	req.URL.Scheme = h.backendURL.Scheme
	req.URL.Host = h.backendURL.Host
	req.RequestURI = ""
	req.Host = h.backendURL.Host
	req.Header.Set("X-Forwarded-For", conn.RemoteAddr().String())
	req.Header.Set("X-Forwarded-Proto", "http")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		logger.Error("Failed to proxy request to backend",
			zap.String("backend", h.config.Backend),
			zap.Error(err))
		http.Error(NewHTTPResponseWriter(conn), "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if err := resp.Write(conn); err != nil {
		logger.Error("Failed to write response to client", zap.Error(err))
		return
	}
}

func (h *ReverseProxyHandler) sendUnauthorized(conn *transport.ClientConnection) {
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

type websocketProxy struct {
	dialer     *websocket.Dialer
	backendURL *url.URL
}

func newWebsocketProxy(backendURL *url.URL, insecureSkipVerify bool) *websocketProxy {
	var tlsConfig *tls.Config
	if backendURL.Scheme == "https" || backendURL.Scheme == "wss" {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
			ServerName:         backendURL.Hostname(),
		}
	}

	return &websocketProxy{
		dialer: &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 45 * time.Second,
			TLSClientConfig:  tlsConfig,
		},
		backendURL: backendURL,
	}
}

func (w *websocketProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request, logger *zap.Logger) {
	backendWsURL := "ws" + strings.TrimPrefix(w.backendURL.String(), "http") + req.URL.Path
	if req.URL.RawQuery != "" {
		backendWsURL += "?" + req.URL.RawQuery
	}

	backendHeaders := make(http.Header)
	for k, v := range req.Header {
		backendHeaders[k] = v
	}
	backendHeaders.Del("Connection")
	backendHeaders.Del("Upgrade")
	backendHeaders.Del("Sec-Websocket-Key")
	backendHeaders.Del("Sec-Websocket-Version")
	backendHeaders.Del("Sec-Websocket-Protocol")
	backendHeaders.Del("Sec-Websocket-Extensions")

	logger.Info("Upgrading connection to WebSocket",
		zap.String("backend", backendWsURL))

	conn, resp, err := w.dialer.Dial(backendWsURL, backendHeaders)
	if err != nil {
		if resp != nil {
			logger.Error("Failed to dial backend WebSocket",
				zap.Error(err),
				zap.Int("status_code", resp.StatusCode),
				zap.String("backend_url", backendWsURL))
		} else {
			logger.Error("Failed to dial backend WebSocket",
				zap.Error(err),
				zap.String("backend_url", backendWsURL))
		}
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	defer conn.Close()

	clientWs, err := upgrader.Upgrade(rw, req, nil)
	if err != nil {
		logger.Error("Failed to upgrade client to WebSocket", zap.Error(err))
		return
	}
	defer clientWs.Close()

	errCh := make(chan error, 2)
	go func() { errCh <- copyWebSocket(clientWs, conn, logger) }()
	go func() { errCh <- copyWebSocket(conn, clientWs, logger) }()

	<-errCh
	<-errCh

	logger.Info("WebSocket connections closed gracefully.",
		zap.String("backend", w.backendURL.String()))
}

func copyWebSocket(dst, src *websocket.Conn, logger *zap.Logger) error {
	for {
		messageType, p, err := src.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) || errors.Is(err, io.EOF) {
				dst.WriteControl(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "normal closure"),
					time.Now().Add(time.Second))
				logger.Debug("WebSocket connection closed normally.", zap.Error(err))
				return nil
			}
			return err
		}

		if err := dst.WriteMessage(messageType, p); err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) || errors.Is(err, io.EOF) {
				logger.Debug("WebSocket write connection closed normally.", zap.Error(err))
				return nil
			}
			return err
		}
	}
}

type HTTPResponseWriter struct {
	conn       *transport.ClientConnection
	header     http.Header
	statusCode int
	written    bool
	w          *bufio.Writer
}

func NewHTTPResponseWriter(conn *transport.ClientConnection) *HTTPResponseWriter {
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
	logger := w.conn.GetLogger()
	if w.written {
		logger.Warn("Ignoring multiple calls to WriteHeader", zap.Int("status_code", statusCode))
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
