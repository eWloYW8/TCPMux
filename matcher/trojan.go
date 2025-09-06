package matcher

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/dlclark/regexp2"
	"github.com/eWloYW8/TCPMux/transport"
)

type TrojanMatcherConfig struct {
	Passwords []string `yaml:"passwords,omitempty"`
}

type TrojanMatcher struct {
	config *TrojanMatcherConfig
	re     *regexp2.Regexp
}

func init() {
	Register("trojan", newTrojanMatcher)
}

func newTrojanMatcher(parameter yaml.Node) (Matcher, error) {
	cfg := &TrojanMatcherConfig{}
	if err := parameter.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode trojan matcher config: %v", err)
	}
	return NewTrojanMatcher(cfg)
}

func NewTrojanMatcher(cfg *TrojanMatcherConfig) (*TrojanMatcher, error) {
	var re *regexp2.Regexp
	if len(cfg.Passwords) > 0 {
		var passwordHashes []string
		for _, password := range cfg.Passwords {
			hash := sha256.Sum224([]byte(password))
			passwordHex := hex.EncodeToString(hash[:])
			passwordHashes = append(passwordHashes, passwordHex)
		}

		pattern := "^(" + strings.Join(passwordHashes, "|") + ")\r\n"
		var err error
		re, err = regexp2.Compile(pattern, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regex pattern: %v", err)
		}
	}
	return &TrojanMatcher{config: cfg, re: re}, nil
}

func (m *TrojanMatcher) Match(conn *transport.BufferedConn) bool {
	if _, ok := conn.Conn.(*tls.Conn); !ok {
		zap.L().Debug("Trojan matcher requires a TLS connection, skipping")
		return false
	}

	data := make([]byte, 58)
	conn.ReadUnconsumed(data)

	if m.re != nil {
		// Trojan protocol starts with hex(SHA224(password)) followed by CRLF.
		match, err := m.re.MatchString(string(data))
		if err != nil {
			zap.L().Error("Trojan password regex match failed", zap.Error(err))
			return false
		}
		if !match {
			zap.L().Debug("Trojan password mismatch")
		}
		return match
	}

	if len(data) >= 58 {
		if data[56] == 0x0D && data[57] == 0x0A {
			return true
		}
	}

	zap.L().Debug("Trojan protocol structure not matched")
	return false
}
