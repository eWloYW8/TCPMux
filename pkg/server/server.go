package server

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/eWloYW8/TCPMux/pkg/config"
	"github.com/eWloYW8/TCPMux/pkg/handler"
	"github.com/eWloYW8/TCPMux/pkg/matcher"
	tlspkg "github.com/eWloYW8/TCPMux/pkg/tls"

	"go.uber.org/zap"
)

const (
	// TLSHandshakeByte is the byte that indicates a TLS handshake.
	TLSHandshakeByte = 0x16 // 22 in decimal
)

type Server struct {
	config    *config.Config
	listeners []net.Listener
	matchers  []matcher.Matcher
	handlers  map[string]handler.Handler
	tlsConfig *tls.Config // Store TLS config here
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

func NewServer(cfg *config.Config) (*Server, error) {
	s := &Server{
		config:   cfg,
		handlers: make(map[string]handler.Handler),
		stopCh:   make(chan struct{}),
	}

	if err := s.initHandlers(); err != nil {
		return nil, err
	}

	if err := s.initMatchers(); err != nil {
		return nil, err
	}

	// Create and store TLS config if enabled
	if cfg.TLS.Enabled {
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

		switch rule.Handler.Type {
		case "passthrough":
			s.handlers[rule.Handler.Name] = handler.NewPassthroughHandler(&rule.Handler)
		default:
			return fmt.Errorf("unknown handler type: %s", rule.Handler.Type)
		}
	}
	return nil
}

func (s *Server) initMatchers() error {
	s.matchers = make([]matcher.Matcher, len(s.config.Rules))
	for i := range s.config.Rules {
		rule := &s.config.Rules[i]
		var m matcher.Matcher
		var err error
		switch rule.Type {
		case "substring":
			m = matcher.NewSubstringMatcher(rule)
		case "regex":
			m, err = matcher.NewRegexMatcher(rule)
			if err != nil {
				return err
			}
		case "default":
			m = matcher.NewDefaultMatcher()
		case "timeout":
			m = matcher.NewTimeoutMatcher()
		default:
			return fmt.Errorf("unknown matcher type: %s", rule.Type)
		}
		s.matchers[i] = m
	}
	return nil
}

func (s *Server) Start() error {
	for _, addr := range s.config.Listen {
		// Always create a standard TCP listener
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
	close(s.stopCh)
	for _, ln := range s.listeners {
		ln.Close()
	}
}

func (s *Server) acceptLoop(ln net.Listener) {
	defer s.wg.Done()
	zap.L().Info("listening for connections", zap.String("addr", ln.Addr().String()))

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				zap.L().Error("failed to accept connection", zap.Error(err))
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(rawConn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			zap.L().Error("panic in handleConnection", zap.Any("panic", r))
			rawConn.Close()
		}
	}()

	// Prepare timeout rule early so TLS detection (Peek) is also covered by the same timeout
	timeoutRule := s.getTimeoutRule()

	// Apply read deadline before peeking to detect TLS so that Peek won't block forever
	if timeoutRule != nil {
		if err := rawConn.SetReadDeadline(time.Now().Add(time.Duration(timeoutRule.Parameter.Timeout) * time.Second)); err != nil {
			zap.L().Error("failed to set read deadline before TLS detection", zap.Error(err))
			rawConn.Close()
			return
		}
	}

	// Use a buffered reader to peek at the initial bytes without consuming them
	br := bufio.NewReader(rawConn)
	processingConn := rawConn // By default, use the raw connection

	// Peek at the first byte to check for TLS handshake
	peekedBytes, err := br.Peek(1)
	if err != nil && err != io.EOF {
		// Handle timeout while peeking
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if timeoutRule != nil {
				// Clear the deadline before handing off to handler
				_ = rawConn.SetReadDeadline(time.Time{})
				zap.L().Info("connection timed out during TLS detection, applying timeout rule", zap.String("rule", timeoutRule.Name))
				if h, ok := s.handlers[timeoutRule.Handler.Name]; ok {
					h.Handle(rawConn)
				} else {
					rawConn.Close()
				}
				return
			}
		}
		zap.L().Error("failed to peek at connection", zap.Error(err))
		rawConn.Close()
		return
	}

	// Clear the deadline set for TLS detection; we'll re-apply for the first read below
	if timeoutRule != nil {
		_ = rawConn.SetReadDeadline(time.Time{})
	}

	// If the connection is closed immediately, peekedBytes will be empty.
	isTLS := false
	if len(peekedBytes) > 0 && s.tlsConfig != nil && peekedBytes[0] == TLSHandshakeByte {
		isTLS = true
	}

	if isTLS {
		zap.L().Debug("TLS connection detected", zap.String("remoteAddr", rawConn.RemoteAddr().String()))
		// If it's a TLS handshake, wrap the connection in a TLS server
		tlsConn := tls.Server(rawConn, s.tlsConfig)
		// Set a deadline for the handshake to complete
		// Use timeout rule value if provided; fallback to 10s otherwise
		handshakeTimeout := 10 * time.Second
		if timeoutRule != nil {
			handshakeTimeout = time.Duration(timeoutRule.Parameter.Timeout) * time.Second
		}
		if err := tlsConn.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
			zap.L().Error("failed to set handshake deadline", zap.Error(err))
			rawConn.Close()
			return
		}

		// The handshake is performed implicitly on the first Read/Write.
		// We will trigger it by reading the first application data packet below.
		processingConn = tlsConn
	} else {
		zap.L().Debug("Plain TCP connection detected", zap.String("remoteAddr", rawConn.RemoteAddr().String()))
		// For plain TCP, we use the buffered reader which has the peeked data.
		// We'll treat the buffered reader as the connection going forward to ensure
		// the peeked byte is included in the first read.
		processingConn = &bufferedConn{br, rawConn}
	}

	buf := make([]byte, 2048) // Increased buffer size for TLS records
	n := 0

	// Handle timeout for the first data packet (or TLS handshake)
	if timeoutRule != nil {
		if err := processingConn.SetReadDeadline(time.Now().Add(time.Duration(timeoutRule.Parameter.Timeout) * time.Second)); err != nil {
			zap.L().Error("failed to set read deadline", zap.Error(err))
			processingConn.Close()
			return
		}
	}

	// This read will either get the first plain TCP packet or
	// trigger the TLS handshake and then read the first decrypted application data packet.
	n, err = processingConn.Read(buf)

	// Clear the deadline after the first read
	if err := processingConn.SetReadDeadline(time.Time{}); err != nil {
		zap.L().Error("failed to clear read deadline", zap.Error(err))
		processingConn.Close()
		return
	}

	if err != nil {
		// Handle timeout error specifically
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if timeoutRule != nil {
				zap.L().Info("connection timed out, applying timeout rule", zap.String("rule", timeoutRule.Name))
				h, ok := s.handlers[timeoutRule.Handler.Name]
				if ok {
					// Don't prepend data, as none was received
					h.Handle(processingConn)
				} else {
					processingConn.Close()
				}
			} else {
				processingConn.Close()
			}
			return
		}

		// For TLS, handshake errors will appear here.
		if isTLS {
			zap.L().Debug("failed to complete TLS handshake or read first data", zap.Error(err))
		} else {
			zap.L().Debug("failed to read from connection", zap.Error(err))
		}
		processingConn.Close()
		return
	}

	data := buf[:n]

	// Find a matching rule for the first data packet
	for i, m := range s.matchers {
		rule := s.config.Rules[i]
		if rule.Type == "timeout" { // Don't match timeout rule here
			continue
		}

		// For TLS required rules, check if the connection was actually a TLS one.
		connIsTLS := false
		if _, ok := processingConn.(*tls.Conn); ok {
			connIsTLS = true
		}

		// The original matcher interface doesn't know about TLS. We add the check here.
		if rule.TLSRequired && !connIsTLS {
			continue
		}

		if m.Match(processingConn, data) {
			zap.L().Info("matched rule",
				zap.String("rule", rule.Name),
				zap.String("handler", rule.Handler.Name),
				zap.String("remoteAddr", processingConn.RemoteAddr().String()))

			h, ok := s.handlers[rule.Handler.Name]
			if !ok {
				zap.L().Error("handler not found for rule", zap.String("rule", rule.Name))
				processingConn.Close()
				return
			}

			// Prepend the first data packet back to the connection so the handler can read it
			finalConn := &prefixedConn{processingConn, data}
			h.Handle(finalConn)
			return
		}
	}

	zap.L().Info("no rule matched, closing connection", zap.String("remoteAddr", processingConn.RemoteAddr().String()))
	processingConn.Close()
}

func (s *Server) getTimeoutRule() *config.Rule {
	for i := range s.config.Rules {
		if s.config.Rules[i].Type == "timeout" {
			return &s.config.Rules[i]
		}
	}
	return nil
}

// prefixedConn is a net.Conn that prepends a buffer to the first read.
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

// bufferedConn wraps a bufio.Reader and a net.Conn to act as a single net.Conn
// This is needed because bufio.Reader itself doesn't satisfy the net.Conn interface (missing SetDeadline etc.)
type bufferedConn struct {
	r *bufio.Reader
	net.Conn
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
