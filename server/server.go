// FILE: server/server.go
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

	// Tracking active connections for graceful shutdown
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

	// Create and store TLS config if enabled
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

		switch rule.Handler.Type {
		case "passthrough":
			s.handlers[rule.Handler.Name] = handler.NewPassthroughHandler(&rule.Handler)
			zap.L().Info(fmt.Sprintf("Initialized passthrough handler. Handler name: %s", rule.Handler.Name))
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
		zap.L().Info(fmt.Sprintf("Initialized matcher. Matcher type: %s, Rule name: %s", rule.Type, rule.Name))
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

	// 1. Close listeners to prevent new connections
	for _, ln := range s.listeners {
		ln.Close()
	}
	zap.L().Info("Listeners closed. No new connections will be accepted.")

	// 2. Signal all connection handlers to start their graceful exit
	close(s.stopCh)

	// 3. Wait for all active connections to close with a timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		zap.L().Info("All active connections handled gracefully.")
	case <-time.After(15 * time.Second): // Graceful shutdown timeout
		zap.L().Warn("Graceful shutdown timed out. Forcibly closing remaining connections.")
		s.connsMux.Lock()
		for conn := range s.activeConns {
			conn.Close()
			zap.L().Warn(fmt.Sprintf("Forcibly closed connection. Remote Addr: %s", conn.RemoteAddr().String()))
		}
		s.connsMux.Unlock()
	}
}

func (s *Server) acceptLoop(ln net.Listener) {
	defer s.wg.Done()
	zap.L().Info(fmt.Sprintf("listening for connections on %s", ln.Addr().String()))

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Check if listener was closed by Stop()
			if opErr, ok := err.(*net.OpError); ok && opErr.Op == "accept" && opErr.Err.Error() == "use of closed network connection" {
				zap.L().Info(fmt.Sprintf("Accept loop shut down gracefully on %s", ln.Addr().String()))
				return
			}
			zap.L().Error(fmt.Sprintf("failed to accept connection: %v", err))
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
		// Cleanup after handler returns
		s.connsMux.Lock()
		delete(s.activeConns, rawConn)
		s.connsMux.Unlock()
		rawConn.Close()
		s.wg.Done()
	}()
	// Prepare timeout rule early so TLS detection (Peek) is also covered by the same timeout
	timeoutRule := s.getTimeoutRule()

	// Apply read deadline before peeking to detect TLS so that Peek won't block forever
	if timeoutRule != nil {
		if err := rawConn.SetReadDeadline(time.Now().Add(time.Duration(timeoutRule.Parameter.Timeout) * time.Second)); err != nil {
			zap.L().Error(fmt.Sprintf("failed to set read deadline before TLS detection: %v", err))
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
				zap.L().Info(fmt.Sprintf("Connection timed out during TLS detection, applying timeout rule: %s, Remote Addr: %s", timeoutRule.Name, rawConn.RemoteAddr().String()))
				if h, ok := s.handlers[timeoutRule.Handler.Name]; ok {
					h.Handle(rawConn)
				} else {
					zap.L().Error(fmt.Sprintf("Timeout handler not found for rule: %s, Handler: %s", timeoutRule.Name, timeoutRule.Handler.Name))
				}
				return
			}
		}
		zap.L().Error(fmt.Sprintf("failed to peek at connection: %v", err))
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
		zap.L().Debug(fmt.Sprintf("TLS connection detected. Remote Addr: %s", rawConn.RemoteAddr().String()))
		// If it's a TLS handshake, wrap the connection in a TLS server
		tlsConn := tls.Server(rawConn, s.tlsConfig)
		// Set a deadline for the handshake to complete
		// Use timeout rule value if provided; fallback to 10s otherwise
		handshakeTimeout := 10 * time.Second
		if timeoutRule != nil {
			handshakeTimeout = time.Duration(timeoutRule.Parameter.Timeout) * time.Second
		}
		if err := tlsConn.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {

			zap.L().Error(fmt.Sprintf("failed to set handshake deadline: %v", err))
			return
		}
		processingConn = tlsConn
	} else {
		zap.L().Debug(fmt.Sprintf("Plain TCP connection detected. Remote Addr: %s", rawConn.RemoteAddr().String()))
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
			zap.L().Error(fmt.Sprintf("failed to set read deadline: %v", err))
			return
		}
	}

	// This read will either get the first plain TCP packet or
	// trigger the TLS handshake and then read the first decrypted application data packet.
	n, err = processingConn.Read(buf)

	// Clear the deadline after the first read
	if err := processingConn.SetReadDeadline(time.Time{}); err != nil {
		zap.L().Error(fmt.Sprintf("failed to clear read deadline: %v", err))
		return
	}

	if err != nil {
		// Handle timeout error specifically
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if timeoutRule != nil {
				zap.L().Info(fmt.Sprintf("Connection timed out, applying timeout rule: %s, Remote Addr: %s", timeoutRule.Name, processingConn.RemoteAddr().String()))
				h, ok := s.handlers[timeoutRule.Handler.Name]
				if ok {
					// Don't prepend data, as none was received
					h.Handle(processingConn)
				} else {
					zap.L().Error(fmt.Sprintf("Timeout handler not found for rule: %s", timeoutRule.Name))
				}
			}
			return
		}

		// For TLS, handshake errors will appear here.
		if isTLS {
			zap.L().Debug(fmt.Sprintf("failed to complete TLS handshake or read first data: %v", err))
		} else {
			zap.L().Debug(fmt.Sprintf("failed to read from connection: %v", err))
		}
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
			zap.L().Debug(fmt.Sprintf("Skipping rule because TLS is required but not detected. Rule: %s, Remote Addr: %s", rule.Name, processingConn.RemoteAddr().String()))
			continue
		}

		if m.Match(processingConn, data) {
			zap.L().Info(fmt.Sprintf("Matched rule: %s, Handler: %s, Remote Addr: %s", rule.Name, rule.Handler.Name, processingConn.RemoteAddr().String()))

			h, ok := s.handlers[rule.Handler.Name]
			if !ok {
				zap.L().Error(fmt.Sprintf("handler not found for rule: %s", rule.Name))
				return
			}

			// Prepend the first data packet back to the connection so the handler can read it
			finalConn := &prefixedConn{processingConn, data}
			h.Handle(finalConn)
			return
		} else {
			zap.L().Debug(fmt.Sprintf("Rule did not match. Rule: %s, Remote Addr: %s", rule.Name, processingConn.RemoteAddr().String()))
		}
	}
	zap.L().Info(fmt.Sprintf("no rule matched, closing connection. Remote Addr: %s", processingConn.RemoteAddr().String()))
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
