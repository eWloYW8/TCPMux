package transport

import (
	"bytes"
	"net"
	"sync"
)

type BufferedConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func NewBufferedConn(c net.Conn) *BufferedConn {
	return &BufferedConn{
		Conn: c,
	}
}

func (bc *BufferedConn) Read(b []byte) (int, error) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if bc.buf.Len() > 0 {
		n, err := bc.buf.Read(b)
		if n > 0 {
			return n, nil
		}
		return n, err
	}
	return bc.Conn.Read(b)
}

func (bc *BufferedConn) ReadUnconsumed(b []byte) (n int, err error) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if bc.buf.Len() == 0 {
		tmp := make([]byte, 8192)
		nRead, err := bc.Conn.Read(tmp)
		if nRead > 0 {
			bc.buf.Write(tmp[:nRead])
			n := copy(b, bc.buf.Bytes())
			return n, nil
		}
		return 0, err
	}
	n = copy(b, bc.buf.Bytes())
	return n, nil
}
