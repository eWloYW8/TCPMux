package matcher

import "net"

type TimeoutMatcher struct{}

func NewTimeoutMatcher() *TimeoutMatcher {
	return &TimeoutMatcher{}
}

func (m *TimeoutMatcher) Match(conn net.Conn, data []byte) bool {
	return len(data) == 0
}
