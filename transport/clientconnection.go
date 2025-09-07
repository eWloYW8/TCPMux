package transport

import (
	"bytes"
	"net"

	"github.com/rs/xid"
	"go.uber.org/zap"
)

type ClientConnection struct {
	net.Conn

	id     xid.ID
	logger *zap.Logger

	buf bytes.Buffer

	bytesRead    uint64
	bytesWritten uint64
	closed       bool

	ruleName    string
	handlerName string
}

func NewClientConnection(c net.Conn) *ClientConnection {
	connID := xid.New()
	logger := zap.L().With(
		zap.String("conn_id", connID.String()),
		zap.String("remote_addr", c.RemoteAddr().String()),
	)

	logger.Info("New connection established")

	return &ClientConnection{
		Conn:   c,
		id:     connID,
		logger: logger,
	}
}

func (c *ClientConnection) Read(b []byte) (int, error) {
	if c.buf.Len() > 0 {
		n, err := c.buf.Read(b)
		if n > 0 {
			c.bytesRead += uint64(n)
			return n, nil
		}
		return n, err
	}
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.bytesRead += uint64(n)
	}
	return n, err
}

func (c *ClientConnection) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.bytesWritten += uint64(n)
	}
	return n, err
}

func (c *ClientConnection) ReadUnconsumed(b []byte) (n int, err error) {
	if c.buf.Len() == 0 {
		tmp := make([]byte, 8192)
		nRead, err := c.Conn.Read(tmp)
		if nRead > 0 {
			c.buf.Write(tmp[:nRead])
			n := copy(b, c.buf.Bytes())
			return n, nil
		}
		return 0, err
	}
	n = copy(b, c.buf.Bytes())
	return n, nil
}

func (c *ClientConnection) GetLogger() *zap.Logger {
	return c.logger
}

func (c *ClientConnection) GetID() xid.ID {
	return c.id
}

func (c *ClientConnection) BytesRead() uint64 {
	return c.bytesRead
}

func (c *ClientConnection) BytesWritten() uint64 {
	return c.bytesWritten
}

func (c *ClientConnection) Close() error {
	if c.closed {
		return nil
	}
	defer c.logger.Info("Connection closed",
		zap.Uint64("bytes_read", c.BytesRead()),
		zap.Uint64("bytes_written", c.BytesWritten()))
	c.closed = true
	return c.Conn.Close()
}

func (c *ClientConnection) SetRuleName(name string) {
	c.ruleName = name
}

func (c *ClientConnection) GetRuleName() string {
	return c.ruleName
}

func (c *ClientConnection) SetHandlerName(name string) {
	c.handlerName = name
}

func (c *ClientConnection) GetHandlerName() string {
	return c.handlerName
}
