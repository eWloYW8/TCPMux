package matcher

import (
	"bytes"
	"fmt"

	"github.com/eWloYW8/TCPMux/transport"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const (
	socks5Version      = 0x05
	socks5authNoAuth   = 0x00
	socks5authUsername = 0x02
)

type Socks5MatcherConfig struct {
	AllowedMethods []string `yaml:"allowed_methods"`
}

type Socks5Matcher struct {
	config *Socks5MatcherConfig
}

func init() {
	Register("socks5", newSocks5Matcher)
}

func newSocks5Matcher(parameter yaml.Node) (Matcher, error) {
	cfg := &Socks5MatcherConfig{}
	if err := parameter.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode SOCKS5 matcher config: %v", err)
	}
	return NewSocks5Matcher(cfg), nil
}

func NewSocks5Matcher(cfg *Socks5MatcherConfig) *Socks5Matcher {
	return &Socks5Matcher{config: cfg}
}

func (m *Socks5Matcher) Match(conn *transport.BufferedConn) bool {
	data := make([]byte, 32)
	conn.ReadUnconsumed(data)
	if len(data) < 2 || data[0] != socks5Version {
		zap.L().Debug("SOCKS5 matcher: handshake invalid or incomplete",
			zap.String("remote_addr", conn.RemoteAddr().String()))
		return false
	}

	nMethods := int(data[1])
	if len(data) < 2+nMethods {
		zap.L().Debug("SOCKS5 matcher: incomplete methods list",
			zap.String("remote_addr", conn.RemoteAddr().String()))
		return false
	}

	clientMethods := data[2 : 2+nMethods]

	if len(m.config.AllowedMethods) == 0 {
		zap.L().Debug("SOCKS5 matcher: no specific method required, accepting any valid handshake",
			zap.String("remote_addr", conn.RemoteAddr().String()))
		return true
	}

	for _, allowedMethod := range m.config.AllowedMethods {
		var methodByte byte
		switch allowedMethod {
		case "no_auth":
			methodByte = socks5authNoAuth
		case "username_password":
			methodByte = socks5authUsername
		default:
			zap.L().Warn("SOCKS5 matcher: unknown method in config", zap.String("method", allowedMethod))
			continue
		}

		if bytes.Contains(clientMethods, []byte{methodByte}) {
			zap.L().Debug("SOCKS5 matcher: authentication method matched",
				zap.String("remote_addr", conn.RemoteAddr().String()),
				zap.String("matched_method", allowedMethod))
			return true
		}
	}

	zap.L().Debug("SOCKS5 matcher: no allowed authentication method found in client request",
		zap.String("remote_addr", conn.RemoteAddr().String()))
	return false
}
