package matcher

import (
	"bytes"
	"net"

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

func (m *SSHMatcher) Match(conn net.Conn, data []byte) bool {
	return bytes.HasPrefix(data, []byte("SSH-"))
}
