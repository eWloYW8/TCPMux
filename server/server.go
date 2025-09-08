package server

import (
	"context"
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

	"github.com/rs/xid"
	"go.uber.org/zap"
)

const (
	TLSHandshakeByte = 0x16
)

type ConnectionInfo struct {
	ID           string `json:"id"`
	RemoteAddr   string `json:"remote_addr"`
	BytesRead    uint64 `json:"bytes_read"`
	BytesWritten uint64 `json:"bytes_written"`
	RuleName     string `json:"rule_name"`
}

type Server struct {
	config            *config.Config
	listeners         []net.Listener
	matchers          []matcher.Matcher
	handlers          map[string]handler.Handler
	tlsConfig         *tls.Config
	timeoutRule       *config.Rule
	wg                sync.WaitGroup
	activeConnections sync.Map
	controllerStop    context.CancelFunc
	rulesMutex        sync.RWMutex
	tlsConfigMutex    sync.RWMutex
}

func NewServer(cfg *config.Config) (*Server, error) {
	s := &Server{
		config:         cfg,
		handlers:       make(map[string]handler.Handler),
		tlsConfigMutex: sync.RWMutex{},
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

func (s *Server) GetActiveConnections() []ConnectionInfo {
	var connections []ConnectionInfo
	s.activeConnections.Range(func(key, value interface{}) bool {
		conn, ok := value.(*transport.ClientConnection)
		if !ok {
			return true
		}
		info := ConnectionInfo{
			ID:           conn.GetID().String(),
			RemoteAddr:   conn.RemoteAddr().String(),
			BytesRead:    conn.BytesRead(),
			BytesWritten: conn.BytesWritten(),
			RuleName:     conn.GetRuleName(),
		}
		connections = append(connections, info)
		return true
	})
	return connections
}

func (s *Server) CloseConnection(id string) bool {
	parsedID, err := xid.FromString(id)
	if err != nil {
		zap.L().Warn("Invalid connection ID provided", zap.String("id", id))
		return false
	}

	if conn, ok := s.activeConnections.Load(parsedID); ok {
		s.activeConnections.Delete(parsedID)
		if clientConn, ok := conn.(*transport.ClientConnection); ok {
			zap.L().Info("Closing connection via API", zap.String("conn_id", id))
			clientConn.Close()
			return true
		}
	}
	zap.L().Info("Connection not found", zap.String("conn_id", id))
	return false
}

func (s *Server) Stop() {
	zap.L().Info("Starting shutdown...")
	if s.controllerStop != nil {
		zap.L().Info("Stopping controller API server...")
		s.controllerStop()
	}

	for _, ln := range s.listeners {
		ln.Close()
	}
	zap.L().Info("Listeners closed. No new connections will be accepted.")

	s.activeConnections.Range(func(key, value interface{}) bool {
		conn := value.(net.Conn)
		conn.Close()
		return true
	})

	zap.L().Info("All active connections closed.")
}

func (s *Server) GetRules() []config.Rule {
	s.rulesMutex.RLock()
	defer s.rulesMutex.RUnlock()
	return s.config.Rules
}

func (s *Server) SetRuleEnabled(index int, enabled bool) bool {
	s.rulesMutex.Lock()
	defer s.rulesMutex.Unlock()
	if index < 0 || index >= len(s.config.Rules) {
		return false
	}
	s.config.Rules[index].Enabled = enabled
	return true
}

func (s *Server) AddRule(rule *config.Rule, index int) bool {
	s.rulesMutex.Lock()
	defer s.rulesMutex.Unlock()

	h, err := handler.NewHandler(rule.Handler.Type, rule.Handler.Parameter)
	if err != nil {
		zap.L().Error("Failed to create handler for new rule", zap.Error(err))
		return false
	}
	s.handlers[rule.Handler.Name] = h

	m, err := matcher.NewMatcher(rule.Type, rule.Parameter)
	if err != nil {
		zap.L().Error("Failed to create matcher for new rule", zap.Error(err))
		return false
	}

	if index < 0 || index > len(s.config.Rules) {
		index = len(s.config.Rules)
	}

	s.config.Rules = append(s.config.Rules[:index], append([]config.Rule{*rule}, s.config.Rules[index:]...)...)
	s.matchers = append(s.matchers[:index], append([]matcher.Matcher{m}, s.matchers[index:]...)...)

	zap.L().Info("Temporary rule added", zap.String("rule_name", rule.Name), zap.Int("index", index))
	return true
}

func (s *Server) RemoveRule(index int) bool {
	s.rulesMutex.Lock()
	defer s.rulesMutex.Unlock()

	if index < 0 || index >= len(s.config.Rules) {
		return false
	}

	if !s.config.Rules[index].IsTemporary {
		zap.L().Warn("Attempted to remove a permanent rule", zap.Int("index", index))
		return false
	}

	rule := s.config.Rules[index]
	s.config.Rules = append(s.config.Rules[:index], s.config.Rules[index+1:]...)
	s.matchers = append(s.matchers[:index], s.matchers[index+1:]...)

	zap.L().Info("Temporary rule removed", zap.String("rule_name", rule.Name), zap.Int("index", index))
	return true
}

func (s *Server) MoveRule(from, to int) bool {
	s.rulesMutex.Lock()
	defer s.rulesMutex.Unlock()

	if from < 0 || from >= len(s.config.Rules) || to < 0 || to >= len(s.config.Rules) {
		zap.L().Warn("Attempted to move rule with invalid indices", zap.Int("from", from), zap.Int("to", to))
		return false
	}

	if from == to {
		return true
	}

	rule := s.config.Rules[from]
	m := s.matchers[from]

	s.config.Rules = append(s.config.Rules[:from], s.config.Rules[from+1:]...)
	s.matchers = append(s.matchers[:from], s.matchers[from+1:]...)

	if to > len(s.config.Rules) {
		to = len(s.config.Rules)
	}
	s.config.Rules = append(s.config.Rules[:to], append([]config.Rule{rule}, s.config.Rules[to:]...)...)
	s.matchers = append(s.matchers[:to], append([]matcher.Matcher{m}, s.matchers[to:]...)...)

	zap.L().Info("Rule moved successfully", zap.Int("from", from), zap.Int("to", to), zap.String("rule_name", rule.Name))
	return true
}

func (s *Server) GetTLSConfig() *config.TLSConfig {
	s.tlsConfigMutex.RLock()
	defer s.tlsConfigMutex.RUnlock()
	return &s.config.TLS
}

func (s *Server) SetTLSConfig(cfg *config.TLSConfig) error {
	s.tlsConfigMutex.Lock()
	defer s.tlsConfigMutex.Unlock()

	newTLSConfig, err := tlspkg.NewTLSConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to create new TLS config: %v", err)
	}

	s.tlsConfig = newTLSConfig
	s.config.TLS = *cfg
	zap.L().Info("TLS configuration updated successfully via API")
	return nil
}

func (s *Server) GetListeners() []string {
	s.rulesMutex.RLock()
	defer s.rulesMutex.RUnlock()

	var addrs []string
	for _, ln := range s.listeners {
		addrs = append(addrs, ln.Addr().String())
	}
	return addrs
}

func (s *Server) GetLoggingConfig() *config.LoggingConfig {
	s.rulesMutex.RLock()
	defer s.rulesMutex.RUnlock()

	cfg := s.config.Logging
	return &cfg
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
	conn := transport.NewClientConnection(rawConn)
	connID := conn.GetID()
	s.activeConnections.Store(connID, conn)

	defer func() {
		conn.Close()
		s.activeConnections.Delete(connID)
		s.wg.Done()
	}()

	logger := conn.GetLogger()

	logger.Debug("Handling new connection")

	var timeout int
	if s.timeoutRule != nil {
		var cfg matcher.TimeoutMatcherConfig
		if err := s.timeoutRule.Parameter.Decode(&cfg); err != nil {
			logger.Error("failed to decode timeout rule parameter", zap.Error(err))
			return
		}
		timeout = cfg.Timeout
	}

	readCh := make(chan struct {
		conn *transport.ClientConnection
		err  error
	}, 1)

	go func() {
		conn, err := s.detectAndUpgradeTLS(conn)
		readCh <- struct {
			conn *transport.ClientConnection
			err  error
		}{conn, err}
	}()

	var clientConn *transport.ClientConnection
	var err error

	if s.timeoutRule != nil {
		select {
		case result := <-readCh:
			clientConn = result.conn
			err = result.err
		case <-time.After(time.Duration(timeout) * time.Second):
			logger.Info("Connection timed out, applying timeout rule",
				zap.String("rule_name", s.timeoutRule.Name))
			s.executeHandler(conn, s.timeoutRule)
			return
		}
	} else {
		result := <-readCh
		clientConn = result.conn
		err = result.err
	}

	if err != nil {
		logger.Error("Failed to read from connection", zap.Error(err))
		return
	}

	if s.findAndExecuteHandler(clientConn) {
		return
	}

	logger.Info("No rule matched, closing connection")
}

func (s *Server) detectAndUpgradeTLS(conn *transport.ClientConnection) (*transport.ClientConnection, error) {
	conn.GetLogger().Debug("Peeking into connection to determine if TLS is used")
	peekedBytes := make([]byte, 1)
	_, err := conn.ReadUnconsumed(peekedBytes)
	if err != nil && err != io.EOF {
		return nil, err
	}

	s.tlsConfigMutex.RLock()
	tlsConfig := s.tlsConfig
	s.tlsConfigMutex.RUnlock()

	if tlsConfig != nil && len(peekedBytes) > 0 && peekedBytes[0] == TLSHandshakeByte {
		conn.GetLogger().Info("TLS connection detected")
		tlsConn := tls.Server(conn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			return nil, fmt.Errorf("failed to complete TLS handshake: %v", err)
		}
		newconn := transport.NewClientConnection(tlsConn)
		conn.GetLogger().Info("TLS handshake completed successfully",
			zap.String("tls_conn", newconn.GetID().String()),
		)
		newconn.GetLogger().Info("Upgraded to TLS connection",
			zap.String("from", conn.GetID().String()),
		)
		return newconn, err
	}
	conn.GetLogger().Debug("Non-TLS connection detected")
	return conn, err
}

func (s *Server) findAndExecuteHandler(conn *transport.ClientConnection) bool {
	logger := conn.GetLogger()
	logger.Debug("Finding matching rule for connection")

	s.rulesMutex.RLock()
	defer s.rulesMutex.RUnlock()

	for i, m := range s.matchers {
		rule := s.config.Rules[i]
		if rule.Type == "timeout" {
			continue
		}

		if !rule.Enabled {
			logger.Debug("Skipping disabled rule", zap.String("rule_name", rule.Name))
			continue
		}

		connIsTLS := false
		if _, ok := conn.Conn.(*tls.Conn); ok {
			connIsTLS = true
		}

		if rule.TLSRequired && !connIsTLS {
			logger.Debug("Skipping rule because TLS is required but not detected",
				zap.String("rule_name", rule.Name),
				zap.String("rule_type", rule.Type),
			)
			continue
		}

		if m.Match(conn) {
			logger.Info("Matched rule", zap.String("rule_name", rule.Name))
			conn.SetRuleName(rule.Name)
			s.executeHandler(conn, &rule)
			return true
		}
		logger.Debug("Rule did not match",
			zap.String("rule_name", rule.Name),
			zap.String("rule_type", rule.Type),
		)
	}
	return false
}

func (s *Server) executeHandler(conn *transport.ClientConnection, rule *config.Rule) {
	logger := conn.GetLogger()
	h, ok := s.handlers[rule.Handler.Name]
	if !ok {
		logger.Error("Handler not found for rule",
			zap.String("rule_name", rule.Name),
			zap.String("handler_name", rule.Handler.Name))
		conn.Close()
		return
	}
	logger.Info("Executing handler",
		zap.String("rule_name", rule.Name),
		zap.String("handler_name", rule.Handler.Name),
		zap.String("handler_type", rule.Handler.Type))
	h.Handle(conn)
}
