package matcher

import (
	"crypto/tls"
	"net"

	"go.uber.org/zap"
)

type TLSMatcherConfig struct {
	SNI  string   `yaml:"sni"`
	ALPN []string `yaml:"alpn"`
}

type TLSMatcher struct {
	config *TLSMatcherConfig
}

// NewTLSMatcher 接收 TLSMatcherConfig 类型
func NewTLSMatcher(cfg *TLSMatcherConfig) *TLSMatcher {
	return &TLSMatcher{config: cfg}
}

func (m *TLSMatcher) Match(conn net.Conn, data []byte) bool {
	tlsConn, ok := conn.(*tls.Conn)
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
