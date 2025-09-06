package matcher

import (
	"bytes"

	"github.com/eWloYW8/TCPMux/transport"
	"gopkg.in/yaml.v3"
)

type SSHMatcher struct{}

func init() {
	Register("ssh", newSSHMatcher)
}

func newSSHMatcher(parameter yaml.Node) (Matcher, error) {
	return NewSSHMatcher(), nil
}

func NewSSHMatcher() *SSHMatcher {
	return &SSHMatcher{}
}

func (m *SSHMatcher) Match(conn *transport.BufferedConn) bool {
	data := make([]byte, 4)
	conn.ReadUnconsumed(data)
	return bytes.HasPrefix(data, []byte("SSH-"))
}
