package matcher

import (
	"crypto/tls"
	"net"

	"github.com/eWloYW8/TCPMux/config"
	"go.uber.org/zap"
)

type TLSMatcher struct {
	rule *config.Rule
}

func NewTLSMatcher(rule *config.Rule) *TLSMatcher {
	return &TLSMatcher{rule: rule}
}

func (m *TLSMatcher) Match(conn net.Conn, data []byte) bool {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return false
	}

	state := tlsConn.ConnectionState()

	if m.rule.Parameter.SNI != "" && m.rule.Parameter.SNI != state.ServerName {
		zap.L().Debug("SNI mismatch",
			zap.String("expected", m.rule.Parameter.SNI),
			zap.String("received", state.ServerName))
		return false
	}

	if len(m.rule.Parameter.ALPN) > 0 {
		var alpnMatch bool
		for _, alpn := range m.rule.Parameter.ALPN {
			if alpn == state.NegotiatedProtocol {
				alpnMatch = true
				break
			}
		}
		if !alpnMatch {
			zap.L().Debug("ALPN mismatch",
				zap.Strings("expected", m.rule.Parameter.ALPN),
				zap.String("received", state.NegotiatedProtocol))
			return false
		}
	}

	return true
}
