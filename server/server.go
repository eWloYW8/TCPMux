package server

import (
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
	transport "github.com/eWloYW8/TCPMux/transport"

	"go.uber.org/zap"
)

const (
	TLSHandshakeByte = 0x16
)

type Server struct {
	config      *config.Config
	listeners   []net.Listener
	matchers    []matcher.Matcher
	handlers    map[string]handler.Handler
	tlsConfig   *tls.Config
	timeoutRule *config.Rule
	wg          sync.WaitGroup
}

func NewServer(cfg *config.Config) (*Server, error) {
	s := &Server{
		config:   cfg,
		handlers: make(map[string]handler.Handler),
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
		h, err := handler.NewHandler(rule.Handler.Type, rule.Handler.Parameter)
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

		if rule.Type == "timeout" {
			s.timeoutRule = rule
		}

		m, err := matcher.NewMatcher(rule.Type, rule.Parameter)
		if err != nil {
			return fmt.Errorf("failed to create matcher for rule %s: %v", rule.Name, err)
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
	zap.L().Info("Starting shutdown...")
	for _, ln := range s.listeners {
		ln.Close()
	}
	zap.L().Info("Listeners closed. No new connections will be accepted.")
}

func (s *Server) acceptLoop(ln net.Listener) {
	defer s.wg.Done()
	zap.L().Info("Listening for connections", zap.String("address", ln.Addr().String()))

	for {
		conn, err := ln.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Op == "accept" && opErr.Err.Error() == "use of closed network connection" {
				zap.L().Info("Accept loop shut down", zap.String("address", ln.Addr().String()))
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
	defer func() {
		rawConn.Close()
		s.wg.Done()
	}()

	zap.L().Info("New connection", zap.String("remote_addr", rawConn.RemoteAddr().String()))

	var timeout int
	if s.timeoutRule != nil {
		var cfg matcher.TimeoutMatcherConfig
		if err := s.timeoutRule.Parameter.Decode(&cfg); err != nil {
			zap.L().Error("failed to decode timeout rule parameter", zap.Error(err))
			return
		}
		timeout = cfg.Timeout
	}

	readCh := make(chan struct {
		conn *transport.BufferedConn
		err  error
	}, 1)

	go func() {
		conn, err := s.initializeConnection(rawConn)
		readCh <- struct {
			conn *transport.BufferedConn
			err  error
		}{conn, err}
	}()

	var peekConn *transport.BufferedConn
	var err error

	if s.timeoutRule != nil {
		select {
		case result := <-readCh:
			peekConn = result.conn
			err = result.err
		case <-time.After(time.Duration(timeout) * time.Second):
			zap.L().Info("Connection timed out, applying timeout rule",
				zap.String("rule_name", s.timeoutRule.Name),
				zap.String("remote_addr", rawConn.RemoteAddr().String()))
			s.executeHandler(rawConn, s.timeoutRule)
			return
		}
	} else {
		result := <-readCh
		peekConn = result.conn
		err = result.err
	}

	if err != nil {
		zap.L().Debug("Failed to read from connection", zap.Error(err), zap.String("remote_addr", rawConn.RemoteAddr().String()))
		return
	}

	if s.findAndExecuteHandler(peekConn) {
		return
	}

	zap.L().Info("No rule matched, closing connection", zap.String("remote_addr", peekConn.RemoteAddr().String()))
}

func (s *Server) initializeConnection(rawConn net.Conn) (*transport.BufferedConn, error) {
	bc := transport.NewBufferedConn(rawConn)
	peekedBytes := make([]byte, 1)
	_, err := bc.ReadUnconsumed(peekedBytes)
	if err != nil && err != io.EOF {
		return nil, err
	}

	if s.tlsConfig != nil && len(peekedBytes) > 0 && peekedBytes[0] == TLSHandshakeByte {
		zap.L().Debug("TLS connection detected", zap.String("remote_addr", rawConn.RemoteAddr().String()))
		tlsConn := tls.Server(bc, s.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			return nil, fmt.Errorf("failed to complete TLS handshake: %v", err)
		}
		return transport.NewBufferedConn(tlsConn), err
	}
	return bc, err
}

func (s *Server) findAndExecuteHandler(conn *transport.BufferedConn) bool {
	for i, m := range s.matchers {
		rule := s.config.Rules[i]
		if rule.Type == "timeout" {
			continue
		}

		connIsTLS := false
		if _, ok := conn.Conn.(*tls.Conn); ok {
			connIsTLS = true
		}

		if rule.TLSRequired && !connIsTLS {
			zap.L().Debug("Skipping rule because TLS is required but not detected",
				zap.String("rule_name", rule.Name),
				zap.String("remote_addr", conn.RemoteAddr().String()))
			continue
		}

		if rule.Type == "tls" && connIsTLS {
			if m.Match(conn) {
				zap.L().Info("Matched TLS rule",
					zap.String("rule_name", rule.Name),
					zap.String("handler_name", rule.Handler.Name),
					zap.String("remote_addr", conn.RemoteAddr().String()))
				s.executeHandler(conn, &rule)
				return true
			}
			continue
		}

		if m.Match(conn) {
			zap.L().Info("Matched rule",
				zap.String("rule_name", rule.Name),
				zap.String("handler_name", rule.Handler.Name),
				zap.String("remote_addr", conn.RemoteAddr().String()))

			s.executeHandler(conn, &rule)
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
