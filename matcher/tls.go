package matcher

import (
	"crypto/tls"
	"fmt"

	"github.com/eWloYW8/TCPMux/transport"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type TLSMatcherConfig struct {
	SNI  string   `yaml:"sni"`
	ALPN []string `yaml:"alpn"`
}

type TLSMatcher struct {
	config *TLSMatcherConfig
}

func init() {
	Register("tls", newTLSMatcher)
}

func newTLSMatcher(parameter yaml.Node) (Matcher, error) {
	cfg := &TLSMatcherConfig{}
	if err := parameter.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode TLS matcher config: %v", err)
	}
	return NewTLSMatcher(cfg), nil
}

func NewTLSMatcher(cfg *TLSMatcherConfig) *TLSMatcher {
	return &TLSMatcher{config: cfg}
}

func (m *TLSMatcher) Match(conn *transport.BufferedConn) bool {
	tlsConn, ok := conn.Conn.(*tls.Conn)
	if !ok {
		return false
	}

	state := tlsConn.ConnectionState()

	if m.config.SNI != "" && m.config.SNI != state.ServerName {
		zap.L().Debug("SNI mismatch",
			zap.String("expected", m.config.SNI),
			zap.String("received", state.ServerName))
		return false
	}

	if len(m.config.ALPN) > 0 {
		var alpnMatch bool
		for _, alpn := range m.config.ALPN {
			if alpn == state.NegotiatedProtocol {
				alpnMatch = true
				break
			}
		}
		if !alpnMatch {
			zap.L().Debug("ALPN mismatch",
				zap.Strings("expected", m.config.ALPN),
				zap.String("received", state.NegotiatedProtocol))
			return false
		}
	}

	return true
}
