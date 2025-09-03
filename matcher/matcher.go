package matcher

import "net"

type Matcher interface {
	Match(conn net.Conn, data []byte) bool
}
