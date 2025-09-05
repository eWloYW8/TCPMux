package handler

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// SOCKS5 version
const (
	socks5Version      = 0x05
	socks5NoAuth       = 0x00
	socks5UserPassAuth = 0x02
)

// SOCKS5 commands
const (
	socks5ConnectCommand = 0x01
)

// SOCKS5 address types
const (
	socks5Ipv4Address   = 0x01
	socks5DomainAddress = 0x03
	socks5Ipv6Address   = 0x04
)

// SOCKS5 replies
const (
	socks5Succeeded               = 0x00
	socks5GeneralFailure          = 0x01
	socks5NotAllowed              = 0x02
	socks5NetworkUnreachable      = 0x03
	socks5HostUnreachable         = 0x04
	socks5ConnectionRefused       = 0x05
	socks5TTLExpired              = 0x06
	socks5CommandNotSupported     = 0x07
	socks5AddressTypeNotSupported = 0x08
)

type Socks5HandlerConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func init() {
	Register("socks5", newSocks5Handler)
}

type Socks5Handler struct {
	config *Socks5HandlerConfig
}

func newSocks5Handler(parameter yaml.Node) (Handler, error) {
	cfg := &Socks5HandlerConfig{}
	if err := parameter.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode socks5 handler config: %v", err)
	}
	return NewSocks5Handler(cfg), nil
}

func NewSocks5Handler(config *Socks5HandlerConfig) *Socks5Handler {
	return &Socks5Handler{config: config}
}

func (h *Socks5Handler) Handle(conn net.Conn) {
	zap.L().Info("Handling connection with socks5 handler",
		zap.String("remote_addr", conn.RemoteAddr().String()))
	defer conn.Close()

	if err := h.handleSocks5(conn); err != nil {
		zap.L().Error("SOCKS5 handler error", zap.Error(err), zap.String("remote_addr", conn.RemoteAddr().String()))
	}
}

func (h *Socks5Handler) handleSocks5(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return fmt.Errorf("failed to read SOCKS5 header: %v", err)
	}

	if header[0] != socks5Version {
		return errors.New("unsupported SOCKS version")
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(reader, methods); err != nil {
		return fmt.Errorf("failed to read SOCKS5 methods: %v", err)
	}

	var selectedMethod byte
	if h.config.Username != "" && h.config.Password != "" {
		found := false
		for _, m := range methods {
			if m == socks5UserPassAuth {
				found = true
				break
			}
		}
		if !found {
			conn.Write([]byte{socks5Version, 0xFF})
			return errors.New("authentication required but client did not offer user/pass method")
		}
		selectedMethod = socks5UserPassAuth
	} else {
		found := false
		for _, m := range methods {
			if m == socks5NoAuth {
				found = true
				break
			}
		}
		if !found {
			conn.Write([]byte{socks5Version, 0xFF})
			return errors.New("client did not offer no-auth method")
		}
		selectedMethod = socks5NoAuth
	}

	conn.Write([]byte{socks5Version, selectedMethod})

	if selectedMethod == socks5UserPassAuth {
		if err := h.authenticate(reader, conn); err != nil {
			return fmt.Errorf("authentication failed: %v", err)
		}
	}

	request := make([]byte, 4)
	if _, err := io.ReadFull(reader, request); err != nil {
		return fmt.Errorf("failed to read SOCKS5 request: %v", err)
	}

	if request[0] != socks5Version {
		h.sendSocks5Reply(conn, socks5GeneralFailure, nil)
		return errors.New("invalid SOCKS5 request version")
	}

	command := request[1]
	if command != socks5ConnectCommand {
		h.sendSocks5Reply(conn, socks5CommandNotSupported, nil)
		return errors.New("SOCKS5 command not supported: " + fmt.Sprintf("0x%x", command))
	}

	addrType := request[3]
	var host string
	var port int

	switch addrType {
	case socks5Ipv4Address:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(reader, ip); err != nil {
			h.sendSocks5Reply(conn, socks5GeneralFailure, nil)
			return fmt.Errorf("failed to read IPv4 address: %v", err)
		}
		host = net.IPv4(ip[0], ip[1], ip[2], ip[3]).String()
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(reader, portBytes); err != nil {
			h.sendSocks5Reply(conn, socks5GeneralFailure, nil)
			return fmt.Errorf("failed to read IPv4 port: %v", err)
		}
		port = int(binary.BigEndian.Uint16(portBytes))
	case socks5DomainAddress:
		domainLen := make([]byte, 1)
		if _, err := io.ReadFull(reader, domainLen); err != nil {
			h.sendSocks5Reply(conn, socks5GeneralFailure, nil)
			return fmt.Errorf("failed to read domain length: %v", err)
		}
		domain := make([]byte, domainLen[0])
		if _, err := io.ReadFull(reader, domain); err != nil {
			h.sendSocks5Reply(conn, socks5GeneralFailure, nil)
			return fmt.Errorf("failed to read domain: %v", err)
		}
		host = string(domain)
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(reader, portBytes); err != nil {
			h.sendSocks5Reply(conn, socks5GeneralFailure, nil)
			return fmt.Errorf("failed to read domain port: %v", err)
		}
		port = int(binary.BigEndian.Uint16(portBytes))
	case socks5Ipv6Address:
		h.sendSocks5Reply(conn, socks5AddressTypeNotSupported, nil)
		return errors.New("IPv6 address type not supported")
	default:
		h.sendSocks5Reply(conn, socks5AddressTypeNotSupported, nil)
		return errors.New("unsupported address type")
	}

	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))

	zap.L().Info("SOCKS5 CONNECT request",
		zap.String("remote_addr", conn.RemoteAddr().String()),
		zap.String("target", targetAddr))

	backendConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		zap.L().Error("Failed to connect to backend", zap.Error(err), zap.String("target", targetAddr))
		replyCode := socks5GeneralFailure
		if opErr, ok := err.(*net.OpError); ok {
			if strings.Contains(opErr.Err.Error(), "refused") {
				replyCode = socks5ConnectionRefused
			} else if strings.Contains(opErr.Err.Error(), "unreachable") {
				replyCode = socks5HostUnreachable
			}
		}
		h.sendSocks5Reply(conn, byte(replyCode), nil)
		return fmt.Errorf("failed to connect to backend %s: %v", targetAddr, err)
	}

	localAddr := backendConn.LocalAddr().(*net.TCPAddr)
	h.sendSocks5Reply(conn, socks5Succeeded, localAddr)

	var wg sync.WaitGroup
	wg.Add(2)

	closeOnce := sync.Once{}
	closeConns := func() {
		closeOnce.Do(func() {
			conn.Close()
			backendConn.Close()
		})
	}

	go func() {
		defer wg.Done()
		_, err := io.Copy(backendConn, reader)
		if err != nil && !isIgnorableError(err) {
			zap.L().Error("Error copying data from client to backend", zap.Error(err))
		}
		closeConns()
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(conn, backendConn)
		if err != nil && !isIgnorableError(err) {
			zap.L().Error("Error copying data from backend to client", zap.Error(err))
		}
		closeConns()
	}()

	wg.Wait()
	zap.L().Info("SOCKS5 connection closed",
		zap.String("remote_addr", conn.RemoteAddr().String()),
		zap.String("target", targetAddr))

	return nil
}

func (h *Socks5Handler) authenticate(reader *bufio.Reader, conn net.Conn) error {
	version := make([]byte, 1)
	if _, err := io.ReadFull(reader, version); err != nil {
		return fmt.Errorf("failed to read auth version: %v", err)
	}
	if version[0] != 0x01 {
		conn.Write([]byte{0x01, 0xFF})
		return errors.New("unsupported authentication version")
	}

	userLen := make([]byte, 1)
	if _, err := io.ReadFull(reader, userLen); err != nil {
		return fmt.Errorf("failed to read username length: %v", err)
	}
	usernameBytes := make([]byte, userLen[0])
	if _, err := io.ReadFull(reader, usernameBytes); err != nil {
		return fmt.Errorf("failed to read username: %v", err)
	}

	passLen := make([]byte, 1)
	if _, err := io.ReadFull(reader, passLen); err != nil {
		return fmt.Errorf("failed to read password length: %v", err)
	}
	passwordBytes := make([]byte, passLen[0])
	if _, err := io.ReadFull(reader, passwordBytes); err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}

	username := string(usernameBytes)
	password := string(passwordBytes)

	if username != h.config.Username || password != h.config.Password {
		conn.Write([]byte{0x01, 0xFF})
		zap.L().Warn("SOCKS5 authentication failed", zap.String("username", username))
		return errors.New("invalid username or password")
	}

	conn.Write([]byte{0x01, 0x00})
	zap.L().Info("SOCKS5 authentication socks5Succeeded", zap.String("username", username))
	return nil
}

func (h *Socks5Handler) sendSocks5Reply(conn net.Conn, rep byte, bindAddr *net.TCPAddr) {
	response := []byte{socks5Version, rep, 0x00}

	if bindAddr != nil {
		if ipv4 := bindAddr.IP.To4(); ipv4 != nil {
			response = append(response, socks5Ipv4Address)
			response = append(response, ipv4...)
		} else {
			response = append(response, socks5Ipv6Address)
			response = append(response, bindAddr.IP...)
		}
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(bindAddr.Port))
		response = append(response, portBytes...)
	} else {
		response = append(response, 0x01, 0, 0, 0, 0, 0, 0)
	}

	conn.Write(response)
}
