package server

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/eWloYW8/TCPMux/config"
	"github.com/eWloYW8/TCPMux/handler"
	"github.com/eWloYW8/TCPMux/matcher"
	tlspkg "github.com/eWloYW8/TCPMux/tls"

	"go.uber.org/zap"
)

const (
	TLSHandshakeByte = 0x16
)

var matcherRegistry = make(map[string]func(*config.Rule) (matcher.Matcher, error))
var handlerRegistry = make(map[string]func(*config.HandlerConfig) (handler.Handler, error))

func init() {
	matcherRegistry["substring"] = func(r *config.Rule) (matcher.Matcher, error) {
		return matcher.NewSubstringMatcher(r), nil
	}
	matcherRegistry["regex"] = func(r *config.Rule) (matcher.Matcher, error) {
		return matcher.NewRegexMatcher(r)
	}
	matcherRegistry["tls"] = func(r *config.Rule) (matcher.Matcher, error) {
		return matcher.NewTLSMatcher(r), nil
	}
	matcherRegistry["default"] = func(r *config.Rule) (matcher.Matcher, error) {
		return matcher.NewDefaultMatcher(), nil
	}
	matcherRegistry["timeout"] = func(r *config.Rule) (matcher.Matcher, error) {
		return matcher.NewTimeoutMatcher(), nil
	}

	handlerRegistry["passthrough"] = func(h *config.HandlerConfig) (handler.Handler, error) {
		return handler.NewPassthroughHandler(h), nil
	}
}

type Server struct {
	config      *config.Config
	listeners   []net.Listener
	matchers    []matcher.Matcher
	handlers    map[string]handler.Handler
	tlsConfig   *tls.Config
	stopCh      chan struct{}
	wg          sync.WaitGroup
	connsMux    sync.Mutex
	activeConns map[net.Conn]struct{}
}

func NewServer(cfg *config.Config) (*Server, error) {
	s := &Server{
		config:      cfg,
		handlers:    make(map[string]handler.Handler),
		stopCh:      make(chan struct{}),
		activeConns: make(map[net.Conn]struct{}),
	}

	if err := s.initHandlers(); err != nil {
		return nil, err
	}

	if err := s.initMatchers(); err != nil {
		return nil, err
	}

	if cfg.TLS.Enabled {
		zap.L().Info("TLS is enabled, creating TLS config")
		tlsConfig, err := tlspkg.NewTLSConfig(&cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %v", err)
		}
		s.tlsConfig = tlsConfig
	}

	return s, nil
}

func (s *Server) initHandlers() error {
	for i := range s.config.Rules {
		rule := &s.config.Rules[i]
		if _, ok := s.handlers[rule.Handler.Name]; ok {
			continue
		}
		factory, ok := handlerRegistry[rule.Handler.Type]
		if !ok {
			return fmt.Errorf("unknown handler type: %s", rule.Handler.Type)
		}
		h, err := factory(&rule.Handler)
		if err != nil {
			return fmt.Errorf("failed to create handler %s: %v", rule.Handler.Name, err)
		}
		s.handlers[rule.Handler.Name] = h
		zap.L().Info("Initialized handler",
			zap.String("handler_name", rule.Handler.Name),
			zap.String("handler_type", rule.Handler.Type))
	}
	return nil
}

func (s *Server) initMatchers() error {
	s.matchers = make([]matcher.Matcher, len(s.config.Rules))
	for i := range s.config.Rules {
		rule := &s.config.Rules[i]
		factory, ok := matcherRegistry[rule.Type]
		if !ok {
			return fmt.Errorf("unknown matcher type: %s", rule.Type)
		}
		m, err := factory(rule)
		if err != nil {
			return fmt.Errorf("failed to create matcher %s: %v", rule.Name, err)
		}
		s.matchers[i] = m
		zap.L().Info("Initialized matcher",
			zap.String("matcher_type", rule.Type),
			zap.String("rule_name", rule.Name))
	}
	return nil
}

func (s *Server) Start() error {
	for _, addr := range s.config.Listen {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %v", addr, err)
		}
		s.listeners = append(s.listeners, ln)
		s.wg.Add(1)
		go s.acceptLoop(ln)
	}

	s.wg.Wait()
	return nil
}

func (s *Server) Stop() {
	zap.L().Info("Starting graceful shutdown...")
	for _, ln := range s.listeners {
		ln.Close()
	}
	zap.L().Info("Listeners closed. No new connections will be accepted.")
	close(s.stopCh)
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		zap.L().Info("All active connections handled gracefully.")
	case <-time.After(5 * time.Second):
		zap.L().Warn("Graceful shutdown timed out. Forcibly closing remaining connections.")
		s.connsMux.Lock()
		for conn := range s.activeConns {
			conn.Close()
			zap.L().Warn("Forcibly closed connection", zap.String("remote_addr", conn.RemoteAddr().String()))
		}
		s.connsMux.Unlock()
	}
}

func (s *Server) acceptLoop(ln net.Listener) {
	defer s.wg.Done()
	zap.L().Info("Listening for connections", zap.String("address", ln.Addr().String()))

	for {
		conn, err := ln.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Op == "accept" && opErr.Err.Error() == "use of closed network connection" {
				zap.L().Info("Accept loop shut down gracefully", zap.String("address", ln.Addr().String()))
				return
			}
			zap.L().Error("Failed to accept connection", zap.Error(err))
			continue
		}
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(rawConn net.Conn) {
	s.connsMux.Lock()
	s.activeConns[rawConn] = struct{}{}
	s.connsMux.Unlock()

	defer func() {
		s.connsMux.Lock()
		delete(s.activeConns, rawConn)
		s.connsMux.Unlock()
		s.wg.Done()
	}()

	zap.L().Info("New connection", zap.String("remote_addr", rawConn.RemoteAddr().String()))

	// Use a single read deadline for initial data/handshake
	timeoutRule := s.getTimeoutRule()
	if timeoutRule != nil {
		if err := rawConn.SetReadDeadline(time.Now().Add(time.Duration(timeoutRule.Parameter.Timeout) * time.Second)); err != nil {
			zap.L().Error("Failed to set read deadline", zap.Error(err), zap.String("remote_addr", rawConn.RemoteAddr().String()))
			return
		}
	}

	conn, data, err := s.peekAndRead(rawConn)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() && timeoutRule != nil {
			zap.L().Info("Connection timed out, applying timeout rule",
				zap.String("rule_name", timeoutRule.Name),
				zap.String("remote_addr", rawConn.RemoteAddr().String()))
			s.executeHandler(rawConn, timeoutRule)
			return
		}
		zap.L().Debug("Failed to peek or read from connection", zap.Error(err), zap.String("remote_addr", rawConn.RemoteAddr().String()))
		return
	}

	// Find and execute handler for matching rule
	if s.findAndExecuteHandler(conn, data) {
		return
	}

	zap.L().Info("No rule matched, closing connection", zap.String("remote_addr", conn.RemoteAddr().String()))
}

// peekAndRead peeks for TLS and reads the first data packet
func (s *Server) peekAndRead(rawConn net.Conn) (net.Conn, []byte, error) {
	br := bufio.NewReader(rawConn)
	peekedBytes, err := br.Peek(1)
	if err != nil && err != io.EOF {
		return nil, nil, err
	}

	if s.tlsConfig != nil && len(peekedBytes) > 0 && peekedBytes[0] == TLSHandshakeByte {
		zap.L().Debug("TLS connection detected", zap.String("remote_addr", rawConn.RemoteAddr().String()))
		tlsConn := tls.Server(rawConn, s.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			return nil, nil, fmt.Errorf("failed to complete TLS handshake: %v", err)
		}
		_ = tlsConn.SetReadDeadline(time.Time{})
		// For TLS connections, we've already done the handshake and the matcher will use the connection state.
		// There's no need to read application data here as TLS matchers don't rely on it.
		return tlsConn, nil, nil
	}

	// For non-TLS, read the first data packet from the buffered reader
	conn := &bufferedConn{br, rawConn}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return nil, nil, err
	}
	_ = rawConn.SetReadDeadline(time.Time{})
	return conn, buf[:n], nil
}

func (s *Server) findAndExecuteHandler(conn net.Conn, data []byte) bool {
	for i, m := range s.matchers {
		rule := s.config.Rules[i]
		if rule.Type == "timeout" {
			continue
		}

		connIsTLS := false
		if _, ok := conn.(*tls.Conn); ok {
			connIsTLS = true
		}

		if rule.TLSRequired && !connIsTLS {
			zap.L().Debug("Skipping rule because TLS is required but not detected",
				zap.String("rule_name", rule.Name),
				zap.String("remote_addr", conn.RemoteAddr().String()))
			continue
		}

		// TLS rules are matched immediately after handshake. Data is nil for those.
		if rule.Type == "tls" && connIsTLS {
			if m.Match(conn, nil) {
				zap.L().Info("Matched TLS rule",
					zap.String("rule_name", rule.Name),
					zap.String("handler_name", rule.Handler.Name),
					zap.String("remote_addr", conn.RemoteAddr().String()))
				s.executeHandler(conn, &rule)
				return true
			}
			continue
		}

		// All other rules are matched on data
		if m.Match(conn, data) {
			zap.L().Info("Matched rule",
				zap.String("rule_name", rule.Name),
				zap.String("handler_name", rule.Handler.Name),
				zap.String("remote_addr", conn.RemoteAddr().String()))

			// Prepend the first data packet back to the connection
			finalConn := &prefixedConn{conn, data}
			s.executeHandler(finalConn, &rule)
			return true
		}
		zap.L().Debug("Rule did not match",
			zap.String("rule_name", rule.Name),
			zap.String("remote_addr", conn.RemoteAddr().String()))
	}
	return false
}

func (s *Server) executeHandler(conn net.Conn, rule *config.Rule) {
	h, ok := s.handlers[rule.Handler.Name]
	if !ok {
		zap.L().Error("Handler not found for rule",
			zap.String("rule_name", rule.Name),
			zap.String("handler_name", rule.Handler.Name))
		conn.Close()
		return
	}
	h.Handle(conn)
}

func (s *Server) getTimeoutRule() *config.Rule {
	for i := range s.config.Rules {
		if s.config.Rules[i].Type == "timeout" {
			return &s.config.Rules[i]
		}
	}
	return nil
}

type prefixedConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixedConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

type bufferedConn struct {
	r *bufio.Reader
	net.Conn
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
