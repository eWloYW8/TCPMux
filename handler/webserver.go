package handler

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type WebServerHandlerConfig struct {
	Dir      string `yaml:"dir"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Index    bool   `yaml:"index"`
}

type WebServerHandler struct {
	config      *WebServerHandlerConfig
	fileHandler http.Handler
}

type noIndexFileSystem struct {
	fs http.FileSystem
}

func (nfs noIndexFileSystem) Open(name string) (http.File, error) {
	f, err := nfs.fs.Open(name)
	if err != nil {
		return nil, err
	}

	s, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	if s.IsDir() {
		index := path.Join(name, "index.html")
		if _, err := nfs.fs.Open(index); err != nil {
			f.Close()
			return nil, os.ErrPermission
		}
	}

	return f, nil
}

func init() {
	Register("webserver", newWebServerHandler)
}

func newWebServerHandler(parameter yaml.Node) (Handler, error) {
	cfg := &WebServerHandlerConfig{}
	if err := parameter.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode webserver handler config: %v", err)
	}
	return NewWebServerHandler(cfg)
}

func NewWebServerHandler(config *WebServerHandlerConfig) (*WebServerHandler, error) {
	if config.Dir == "" {
		return nil, fmt.Errorf("'dir' parameter for webserver handler cannot be empty")
	}

	handler := &WebServerHandler{
		config: config,
	}

	var fileSystem http.FileSystem = http.Dir(config.Dir)
	if !config.Index {
		fileSystem = noIndexFileSystem{fileSystem}
	}

	fileSrv := http.FileServer(fileSystem)

	handler.fileHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler.config.Username != "" || handler.config.Password != "" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != handler.config.Username || pass != handler.config.Password {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		fileSrv.ServeHTTP(w, r)
	})

	return handler, nil
}

func (h *WebServerHandler) Handle(conn net.Conn) {
	defer conn.Close()
	zap.L().Info("Handling connection with webserver handler",
		zap.String("dir", h.config.Dir),
		zap.String("remote_addr", conn.RemoteAddr().String()))

	reader := bufio.NewReader(conn)

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				zap.L().Debug("Failed to read HTTP request", zap.Error(err))
			}
			return
		}

		res := &connResponseWriter{conn: conn, header: make(http.Header)}

		h.fileHandler.ServeHTTP(res, req)

		fmt.Fprint(res.conn, "0\r\n\r\n")

		if req.Close {
			break
		}
	}
}

type connResponseWriter struct {
	conn        net.Conn
	header      http.Header
	statusCode  int
	wroteHeader bool
}

func (w *connResponseWriter) Header() http.Header {
	return w.header
}

func (w *connResponseWriter) writeHeaders() {
	if w.wroteHeader {
		return
	}
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}

	w.header.Set("Transfer-Encoding", "chunked")

	fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n", w.statusCode, http.StatusText(w.statusCode))

	w.header.Write(w.conn)

	fmt.Fprint(w.conn, "\r\n")

	w.wroteHeader = true
}

func (w *connResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.writeHeaders()
}

func (w *connResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	n, err := fmt.Fprintf(w.conn, "%x\r\n%s\r\n", len(b), b)
	if err != nil {
		return 0, err
	}
	return n - (len(fmt.Sprintf("%x\r\n", len(b))) + len("\r\n")), nil
}
