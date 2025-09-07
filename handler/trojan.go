package handler

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/eWloYW8/TCPMux/transport"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Trojan commands
const (
	trojanConnectCommand   = 0x01
	trojanAssociateCommand = 0x03
	crlf                   = "\r\n"
	trojanPacketMaxPayload = 65487
)

// Trojan address types
const (
	trojanIPv4Address   = 0x01
	trojanDomainAddress = 0x03
	trojanIPv6Address   = 0x04
)

type TrojanHandlerConfig struct {
	Passwords []string `yaml:"passwords"`
}

func init() {
	Register("trojan", newTrojanHandler)
}

type TrojanHandler struct {
	config *TrojanHandlerConfig
}

func newTrojanHandler(parameter yaml.Node) (Handler, error) {
	cfg := &TrojanHandlerConfig{}
	if err := parameter.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode trojan handler config: %v", err)
	}
	return NewTrojanHandler(cfg), nil
}

func NewTrojanHandler(config *TrojanHandlerConfig) *TrojanHandler {
	return &TrojanHandler{config: config}
}

func (h *TrojanHandler) Handle(conn *transport.ClientConnection) {
	logger := conn.GetLogger()
	logger.Info("Handling connection with trojan handler")
	defer conn.Close()

	if err := h.handleTrojan(conn); err != nil {
		logger.Error("Trojan handler error", zap.Error(err))
	}
}

func (h *TrojanHandler) handleTrojan(conn *transport.ClientConnection) error {
	logger := conn.GetLogger()
	reader := bufio.NewReader(conn)

	receivedHashHex := make([]byte, 56)
	if _, err := io.ReadFull(reader, receivedHashHex); err != nil {
		return fmt.Errorf("failed to read password hash: %v", err)
	}

	receivedHash := make([]byte, 28)
	if _, err := hex.Decode(receivedHash, receivedHashHex); err != nil {
		return fmt.Errorf("failed to decode hex hash: %v", err)
	}

	authenticated := false
	for _, p := range h.config.Passwords {
		expectedHash := sha224Hash(p)
		if bytes.Equal(receivedHash, expectedHash) {
			authenticated = true
			break
		}
	}

	if !authenticated {
		return errors.New("invalid password")
	}

	// 2. Read the first CRLF
	if _, err := readCRLF(reader); err != nil {
		return fmt.Errorf("failed to read first CRLF: %v", err)
	}

	// 3. Read the SOCKS5-like request
	command, err := reader.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read command: %v", err)
	}
	host, port, err := h.readAddress(reader)
	if err != nil {
		return fmt.Errorf("failed to read address: %v", err)
	}
	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))

	// 4. Read the second CRLF
	if _, err := readCRLF(reader); err != nil {
		return fmt.Errorf("failed to read second CRLF: %v", err)
	}

	logger.Info("Trojan request received",
		zap.String("command", fmt.Sprintf("0x%x", command)),
		zap.String("target", targetAddr))

	// 5. Handle the command
	switch command {
	case trojanConnectCommand:
		return h.handleConnect(conn, reader, targetAddr)
	case trojanAssociateCommand:
		return h.handleAssociate(conn, reader)
	default:
		return fmt.Errorf("unsupported command: 0x%x", command)
	}
}

// sha224Hash computes the SHA224 hash of a given password string.
func sha224Hash(password string) []byte {
	h := sha256.New224()
	h.Write([]byte(password))
	return h.Sum(nil)
}

// readCRLF reads a CRLF and returns an error if it's not present.
func readCRLF(r *bufio.Reader) ([]byte, error) {
	crlfBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, crlfBytes); err != nil {
		return nil, err
	}
	if string(crlfBytes) != crlf {
		return nil, errors.New("invalid CRLF")
	}
	return crlfBytes, nil
}

func (h *TrojanHandler) readAddress(reader *bufio.Reader) (host string, port int, err error) {
	addrTypeByte, err := reader.ReadByte()
	if err != nil {
		return "", 0, fmt.Errorf("unable to read address type: %w", err)
	}

	switch addrType := addrTypeByte; addrType {
	case trojanIPv4Address:
		ipBytes := make([]byte, 4)
		if _, err := io.ReadFull(reader, ipBytes); err != nil {
			return "", 0, fmt.Errorf("failed to read IPv4: %w", err)
		}
		host = net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]).String()
	case trojanIPv6Address:
		ipBytes := make([]byte, 16)
		if _, err := io.ReadFull(reader, ipBytes); err != nil {
			return "", 0, fmt.Errorf("failed to read IPv6: %w", err)
		}
		host = net.IP(ipBytes).String()
	case trojanDomainAddress:
		domainLenByte, err := reader.ReadByte()
		if err != nil {
			return "", 0, fmt.Errorf("failed to read domain length: %w", err)
		}
		domainBytes := make([]byte, domainLenByte)
		if _, err := io.ReadFull(reader, domainBytes); err != nil {
			return "", 0, fmt.Errorf("failed to read domain: %w", err)
		}
		host = string(domainBytes)
	default:
		return "", 0, fmt.Errorf("invalid address type: %d", addrType)
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return "", 0, fmt.Errorf("failed to read port: %w", err)
	}
	port = int(binary.BigEndian.Uint16(portBytes))

	return host, port, nil
}

// handles the TCP CONNECT command.
func (h *TrojanHandler) handleConnect(clientConn *transport.ClientConnection, reader *bufio.Reader, targetAddr string) error {
	logger := clientConn.GetLogger()
	backendConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		logger.Error("Failed to connect to backend", zap.Error(err), zap.String("target", targetAddr))
		return fmt.Errorf("failed to connect to backend %s: %v", targetAddr, err)
	}
	defer backendConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(backendConn, reader)
		if conn, ok := backendConn.(*net.TCPConn); ok {
			conn.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, backendConn)
		if conn, ok := clientConn.Conn.(*net.TCPConn); ok {
			conn.CloseWrite()
		}
	}()

	wg.Wait()
	logger.Info("Trojan TCP connection closed", zap.String("target", targetAddr))
	return nil
}

// handles the UDP ASSOCIATE command.
func (h *TrojanHandler) handleAssociate(clientConn *transport.ClientConnection, reader *bufio.Reader) error {
	logger := clientConn.GetLogger()
	connTable := make(map[string]net.Conn)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var closeOnce sync.Once

	closeAllConns := func() {
		closeOnce.Do(func() {
			mu.Lock()
			defer mu.Unlock()
			for _, c := range connTable {
				c.Close()
			}
			clientConn.Close()
		})
	}

	downlink := func(udpConn *net.UDPConn) {
		defer wg.Done()
		defer closeAllConns()

		buf := make([]byte, trojanPacketMaxPayload)
		packetBuffer := new(bytes.Buffer)

		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}

			packetBuffer.Reset()

			var addrType byte
			var ipBytes []byte
			if ipv4 := addr.IP.To4(); ipv4 != nil {
				addrType = trojanIPv4Address
				ipBytes = ipv4
			} else {
				addrType = trojanIPv6Address
				ipBytes = addr.IP
			}
			packetBuffer.WriteByte(addrType)
			packetBuffer.Write(ipBytes)
			portBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(portBytes, uint16(addr.Port))
			packetBuffer.Write(portBytes)

			// Marshal Length and CRLF
			lengthBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(lengthBytes, uint16(n))
			packetBuffer.Write(lengthBytes)
			packetBuffer.WriteString(crlf)

			packetBuffer.Write(buf[:n])

			clientConn.Write(packetBuffer.Bytes())
		}
	}

	upLink := func() {
		defer wg.Done()
		defer closeAllConns()

		for {
			host, port, err := h.readAddress(reader)
			if err != nil {
				break
			}

			lengthBytes := make([]byte, 2)
			if _, err := io.ReadFull(reader, lengthBytes); err != nil {
				break
			}
			length := int(binary.BigEndian.Uint16(lengthBytes))

			if _, err := readCRLF(reader); err != nil {
				break
			}

			payload := make([]byte, length)
			if _, err := io.ReadFull(reader, payload); err != nil {
				break
			}

			targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
			mu.Lock()
			targetConn, exists := connTable[targetAddr]
			if !exists {
				var err error
				targetConn, err = net.Dial("udp", targetAddr)
				if err != nil {
					mu.Unlock()
					continue
				}
				connTable[targetAddr] = targetConn
				wg.Add(1)
				go downlink(targetConn.(*net.UDPConn))
			}
			mu.Unlock()

			targetConn.Write(payload)
		}
	}

	wg.Add(1)
	go upLink()

	wg.Wait()

	logger.Info("Trojan UDP association closed")
	return nil
}
