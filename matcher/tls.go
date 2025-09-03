package matcher

import (
	"crypto/tls"
	"net"

	"github.com/eWloYW8/TCPMux/config"
	"go.uber.org/zap"
)

// TLSMatcher checks SNI and ALPN values from a TLS connection's state.
type TLSMatcher struct {
	rule *config.Rule
}

// NewTLSMatcher creates a new TLSMatcher.
func NewTLSMatcher(rule *config.Rule) *TLSMatcher {
	return &TLSMatcher{rule: rule}
}

// Match checks if the connection's SNI and ALPN values match the rule's parameters.
func (m *TLSMatcher) Match(conn net.Conn, data []byte) bool {
	// The matcher should only be used on TLS connections.
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return false
	}

	state := tlsConn.ConnectionState()

	// Match SNI if configured.
	if m.rule.Parameter.SNI != "" {
		if m.rule.Parameter.SNI != state.ServerName {
			zap.L().Debug("SNI mismatch", zap.String("expected", m.rule.Parameter.SNI), zap.String("received", state.ServerName))
			return false
		}
	}

	// Match ALPN if configured.
	if len(m.rule.Parameter.ALPN) > 0 {
		var alpnMatch bool
		for _, alpn := range m.rule.Parameter.ALPN {
			if alpn == state.NegotiatedProtocol {
				alpnMatch = true
				break
			}
		}
		if !alpnMatch {
			zap.L().Debug("ALPN mismatch", zap.Strings("expected", m.rule.Parameter.ALPN), zap.String("received", state.NegotiatedProtocol))
			return false
		}
	}

	return true
}
