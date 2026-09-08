package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
)

// ============================================================================
// Password Provider Stub
// ============================================================================

// getPassword returns the password (or auth token) for the specified user.
// Stub implementation to be customized by the user (e.g., generating AWS RDS IAM auth tokens).
func getPassword(user string, cfg *Config) (string, error) {
	token, err := auth.BuildAuthToken(context.Background(), cfg.TargetAddr, cfg.Region, user, cfg.Credentials)
	log.Printf("[auth] getPassword called for user: %q", user)
	return token, err
}

// ============================================================================
// PostgreSQL Protocol Constants
// ============================================================================

const (
	sslRequestCode    uint32 = 80877103 // 1234 << 16 | 5679
	gssEncRequestCode uint32 = 80877104 // 1234 << 16 | 5680
	cancelRequestCode uint32 = 80877102 // 1234 << 16 | 5678
	protocolVersion3  uint32 = 196608   // 3 << 16 | 0

	sslNotAllowed byte = 'N'

	authTypeOk                uint32 = 0
	authTypeKerberosV5        uint32 = 2
	authTypeCleartextPassword uint32 = 3
	authTypeMD5Password       uint32 = 5
	authTypeSCM               uint32 = 6
	authTypeGSS               uint32 = 7
	authTypeGSSContinue       uint32 = 8
	authTypeSSPI              uint32 = 9
	authTypeSASL              uint32 = 10
	authTypeSASLContinue      uint32 = 11
	authTypeSASLFinal         uint32 = 12
)

// ============================================================================
// Configuration
// ============================================================================

type Config struct {
	Credentials   aws.CredentialsProvider
	Region        string
	ListenAddr    string
	TargetAddr    string
	SSLMode       string // "disable", "prefer", "require"
	TLSSkipVerify bool
}

// ============================================================================
// Startup Message Parsing & Building
// ============================================================================

type StartupInfo struct {
	User       string
	Database   string
	Parameters map[string]string
}

// parseStartupParameters extracts null-terminated key-value pairs from the startup packet body.
func parseStartupParameters(payload []byte) (map[string]string, error) {
	params := make(map[string]string)
	idx := 0
	for idx < len(payload) {
		if payload[idx] == 0 {
			break
		}
		nullIdx := bytes.IndexByte(payload[idx:], 0)
		if nullIdx == -1 {
			return nil, errors.New("malformed parameter name: missing null terminator")
		}
		key := string(payload[idx : idx+nullIdx])
		idx += nullIdx + 1
		if idx >= len(payload) {
			return nil, errors.New("malformed parameter value: missing null terminator")
		}
		nullIdx = bytes.IndexByte(payload[idx:], 0)
		if nullIdx == -1 {
			return nil, errors.New("malformed parameter value: missing null terminator")
		}
		val := string(payload[idx : idx+nullIdx])
		idx += nullIdx + 1
		params[key] = val
	}
	return params, nil
}

// buildStartupMessage constructs a PostgreSQL 3.0 StartupMessage packet.
func buildStartupMessage(params map[string]string) []byte {
	var buf bytes.Buffer
	// Placeholder for 4-byte total length
	buf.Write([]byte{0, 0, 0, 0})
	// Protocol version 3.0
	var proto [4]byte
	binary.BigEndian.PutUint32(proto[:], protocolVersion3)
	buf.Write(proto[:])

	for k, v := range params {
		buf.WriteString(k)
		buf.WriteByte(0)
		buf.WriteString(v)
		buf.WriteByte(0)
	}
	// Final terminating null byte
	buf.WriteByte(0)

	msg := buf.Bytes()
	binary.BigEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

// ============================================================================
// Error Response Generation
// ============================================================================

// buildErrorResponse formats a standard PostgreSQL ErrorResponse ('E') message.
func buildErrorResponse(severity, code, message string) []byte {
	var buf bytes.Buffer
	buf.WriteByte('E')
	// Placeholder for 4-byte length
	buf.Write([]byte{0, 0, 0, 0})

	buf.WriteByte('S')
	buf.WriteString(severity)
	buf.WriteByte(0)

	buf.WriteByte('C')
	buf.WriteString(code)
	buf.WriteByte(0)

	buf.WriteByte('M')
	buf.WriteString(message)
	buf.WriteByte(0)

	buf.WriteByte(0) // Message terminator

	data := buf.Bytes()
	binary.BigEndian.PutUint32(data[1:5], uint32(len(data)-1))
	return data
}

// ============================================================================
// Client Handshake
// ============================================================================

// handleClientHandshake negotiates SSL/GSS flags with client and reads the StartupMessage.
func handleClientHandshake(client net.Conn) (*StartupInfo, error) {
	var header [8]byte
	for {
		if _, err := io.ReadFull(client, header[:]); err != nil {
			return nil, fmt.Errorf("reading client startup header: %w", err)
		}
		length := binary.BigEndian.Uint32(header[0:4])
		code := binary.BigEndian.Uint32(header[4:8])

		if length == 8 && (code == sslRequestCode || code == gssEncRequestCode) {
			// Reply 'N' (SSL / GSS not supported on this local listener)
			if _, err := client.Write([]byte{sslNotAllowed}); err != nil {
				return nil, fmt.Errorf("writing ssl/gss rejection: %w", err)
			}
			// Client will send the actual StartupMessage next
			continue
		}

		if code == cancelRequestCode {
			return nil, errors.New("received cancel request on client connection")
		}

		if code != protocolVersion3 {
			return nil, fmt.Errorf("unsupported client protocol version: %d", code)
		}

		if length < 8 {
			return nil, fmt.Errorf("invalid startup message length: %d", length)
		}

		payload := make([]byte, length-8)
		if _, err := io.ReadFull(client, payload); err != nil {
			return nil, fmt.Errorf("reading startup parameters: %w", err)
		}

		params, err := parseStartupParameters(payload)
		if err != nil {
			return nil, fmt.Errorf("parsing startup parameters: %w", err)
		}

		user := params["user"]
		if user == "" {
			return nil, errors.New("missing user in client startup message")
		}

		database := params["database"]
		if database == "" {
			database = user
			params["database"] = user
		}

		return &StartupInfo{
			User:       user,
			Database:   database,
			Parameters: params,
		}, nil
	}
}

// ============================================================================
// Target Database Connection & Authentication
// ============================================================================

// connectTarget dials the backend PostgreSQL server and optionally negotiates TLS.
func connectTarget(cfg *Config) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", cfg.TargetAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dialing target %s: %w", cfg.TargetAddr, err)
	}

	if cfg.SSLMode == "disable" {
		return conn, nil
	}

	// Send SSLRequest: [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]
	var sslReq [8]byte
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], sslRequestCode)
	if _, err := conn.Write(sslReq[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("sending SSLRequest to target: %w", err)
	}

	var resp [1]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading SSLRequest response: %w", err)
	}

	if resp[0] == 'S' {
		// Server supports SSL, upgrade connection
		host := cfg.TargetAddr
		if h, _, err := net.SplitHostPort(cfg.TargetAddr); err == nil {
			host = h
		}
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: cfg.TLSSkipVerify,
		})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake with target failed: %w", err)
		}
		return tlsConn, nil
	} else if resp[0] == 'N' {
		if cfg.SSLMode == "require" {
			conn.Close()
			return nil, errors.New("target rejected SSL, but sslmode=require")
		}
		// sslmode=prefer: proceed unencrypted
		return conn, nil
	}

	conn.Close()
	return nil, fmt.Errorf("unexpected SSL response from target: %q", resp[0])
}

// authenticateTarget sends StartupMessage to target, handles auth challenges, and returns once AuthOk is received.
func authenticateTarget(target net.Conn, client net.Conn, info *StartupInfo, password string) error {
	// 1. Send StartupMessage to backend
	startupMsg := buildStartupMessage(info.Parameters)
	if _, err := target.Write(startupMsg); err != nil {
		return fmt.Errorf("sending startup message to target: %w", err)
	}

	// 2. Loop reading auth challenges until AuthenticationOk ('R', type 0)
	var scram *scramClientState

	for {
		var hdr [5]byte
		if _, err := io.ReadFull(target, hdr[:]); err != nil {
			return fmt.Errorf("reading target response header: %w", err)
		}

		msgType := hdr[0]
		msgLen := binary.BigEndian.Uint32(hdr[1:5])
		if msgLen < 4 {
			return fmt.Errorf("invalid message length from target: %d", msgLen)
		}

		payload := make([]byte, msgLen-4)
		if _, err := io.ReadFull(target, payload); err != nil {
			return fmt.Errorf("reading target message payload: %w", err)
		}

		// Handle error response from target
		if msgType == 'E' {
			// Forward backend error to client so client sees the exact failure
			_, _ = client.Write(hdr[:])
			_, _ = client.Write(payload)
			return errors.New("target database returned error response")
		}

		if msgType != 'R' {
			return fmt.Errorf("unexpected message type from target: %c", msgType)
		}

		if len(payload) < 4 {
			return errors.New("authentication packet payload too short")
		}

		authType := binary.BigEndian.Uint32(payload[0:4])
		switch authType {
		case authTypeOk:
			// Authentication successful!
			// Forward AuthenticationOk directly to client.
			if _, err := client.Write(hdr[:]); err != nil {
				return fmt.Errorf("forwarding AuthenticationOk to client: %w", err)
			}
			if _, err := client.Write(payload); err != nil {
				return fmt.Errorf("forwarding AuthenticationOk payload to client: %w", err)
			}
			// The connection is now authenticated!
			// Subsequent messages ('S' ParameterStatus, 'K' BackendKeyData, 'Z' ReadyForQuery)
			// will be forwarded by the streaming copy loop.
			return nil

		case authTypeCleartextPassword:
			if err := sendPasswordMessage(target, password); err != nil {
				return fmt.Errorf("sending cleartext password: %w", err)
			}

		case authTypeMD5Password:
			if len(payload) < 8 {
				return errors.New("malformed MD5 auth request: missing 4-byte salt")
			}
			salt := payload[4:8]
			token := computeMD5Password(password, info.User, salt)
			if err := sendPasswordMessage(target, token); err != nil {
				return fmt.Errorf("sending MD5 password: %w", err)
			}

		case authTypeSASL:
			var err error
			scram, err = newSCRAMClient(info.User, password, payload[4:])
			if err != nil {
				return fmt.Errorf("initiating SCRAM auth: %w", err)
			}
			if err := scram.sendInitialMessage(target); err != nil {
				return fmt.Errorf("sending SCRAM initial response: %w", err)
			}

		case authTypeSASLContinue:
			if scram == nil {
				return errors.New("received SASLContinue without initial SASL request")
			}
			if err := scram.handleServerFirst(target, payload[4:]); err != nil {
				return fmt.Errorf("handling SCRAM server first message: %w", err)
			}

		case authTypeSASLFinal:
			if scram == nil {
				return errors.New("received SASLFinal without initial SASL request")
			}
			if err := scram.handleServerFinal(payload[4:]); err != nil {
				return fmt.Errorf("handling SCRAM server final message: %w", err)
			}

		default:
			return fmt.Errorf("unsupported authentication type from target: %d", authType)
		}
	}
}

// sendPasswordMessage sends a standard PostgreSQL PasswordMessage ('p').
func sendPasswordMessage(w io.Writer, password string) error {
	msg := append([]byte(password), 0)
	length := uint32(4 + len(msg))
	var hdr [5]byte
	hdr[0] = 'p'
	binary.BigEndian.PutUint32(hdr[1:5], length)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

// computeMD5Password computes the PostgreSQL MD5 authentication response:
// "md5" + md5(hex(md5(password + user)) + salt)
func computeMD5Password(password, user string, salt []byte) string {
	h1 := md5.Sum([]byte(password + user))
	h1Hex := hex.EncodeToString(h1[:])

	h2 := md5.New()
	h2.Write([]byte(h1Hex))
	h2.Write(salt)
	return "md5" + hex.EncodeToString(h2.Sum(nil))
}

// ============================================================================
// SCRAM-SHA-256 Authentication (RFC 5802 / RFC 7677)
// ============================================================================

type scramClientState struct {
	user                 string
	password             string
	clientNonce          string
	clientFirstBare      string
	serverSignatureCheck []byte
}

func newSCRAMClient(user, password string, payload []byte) (*scramClientState, error) {
	// Parse supported SASL mechanisms
	var mechs []string
	idx := 0
	for idx < len(payload) {
		if payload[idx] == 0 {
			break
		}
		nullIdx := bytes.IndexByte(payload[idx:], 0)
		if nullIdx == -1 {
			break
		}
		mechs = append(mechs, string(payload[idx:idx+nullIdx]))
		idx += nullIdx + 1
	}

	hasScram := false
	for _, m := range mechs {
		if m == "SCRAM-SHA-256" {
			hasScram = true
			break
		}
	}
	if !hasScram {
		return nil, fmt.Errorf("target does not support SCRAM-SHA-256, offered: %v", mechs)
	}

	// Generate 18 random bytes -> 24 base64 chars
	rawNonce := make([]byte, 18)
	if _, err := rand.Read(rawNonce); err != nil {
		return nil, fmt.Errorf("generating random nonce: %w", err)
	}
	nonce := base64.StdEncoding.EncodeToString(rawNonce)

	return &scramClientState{
		user:        user,
		password:    password,
		clientNonce: nonce,
	}, nil
}

func (s *scramClientState) sendInitialMessage(w io.Writer) error {
	s.clientFirstBare = "n=,r=" + s.clientNonce
	clientFirstMessage := "n,," + s.clientFirstBare

	mech := "SCRAM-SHA-256\x00"
	bodyLen := len(mech) + 4 + len(clientFirstMessage)
	msgLen := uint32(4 + bodyLen)

	var buf bytes.Buffer
	buf.WriteByte('p')
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], msgLen)
	buf.Write(lenBuf[:])

	buf.WriteString(mech)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(clientFirstMessage)))
	buf.Write(lenBuf[:])
	buf.WriteString(clientFirstMessage)

	_, err := w.Write(buf.Bytes())
	return err
}

func (s *scramClientState) handleServerFirst(w io.Writer, payload []byte) error {
	serverFirst := string(payload)
	parts := strings.Split(serverFirst, ",")
	var r, saltB64 string
	var iterations int

	for _, p := range parts {
		if strings.HasPrefix(p, "r=") {
			r = p[2:]
		} else if strings.HasPrefix(p, "s=") {
			saltB64 = p[2:]
		} else if strings.HasPrefix(p, "i=") {
			var err error
			iterations, err = strconv.Atoi(p[2:])
			if err != nil {
				return fmt.Errorf("invalid SCRAM iteration count: %w", err)
			}
		}
	}

	if !strings.HasPrefix(r, s.clientNonce) {
		return errors.New("server nonce does not match client nonce")
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return fmt.Errorf("invalid salt base64: %w", err)
	}

	channelBinding := "c=biws" // "biws" is base64 of "n,,"
	clientFinalWithoutProof := channelBinding + ",r=" + r
	authMessage := s.clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof

	saltedPassword := pbkdf2Sha256([]byte(s.password), salt, iterations, 32)
	clientKey := hmacSha256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	clientSignature := hmacSha256(storedKey[:], []byte(authMessage))
	clientProof := xorBytes(clientKey, clientSignature)

	serverKey := hmacSha256(saltedPassword, []byte("Server Key"))
	s.serverSignatureCheck = hmacSha256(serverKey, []byte(authMessage))

	clientFinalMessage := clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(clientProof)

	// Send PasswordMessage ('p') with client final response (no null terminator in SASL response)
	msgLen := uint32(4 + len(clientFinalMessage))
	var buf bytes.Buffer
	buf.WriteByte('p')
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], msgLen)
	buf.Write(lenBuf[:])
	buf.WriteString(clientFinalMessage)

	_, err = w.Write(buf.Bytes())
	return err
}

func (s *scramClientState) handleServerFinal(payload []byte) error {
	serverFinal := string(payload)
	parts := strings.Split(serverFinal, ",")
	for _, p := range parts {
		if strings.HasPrefix(p, "v=") {
			sig, err := base64.StdEncoding.DecodeString(p[2:])
			if err != nil {
				return fmt.Errorf("decoding server signature: %w", err)
			}
			if !hmac.Equal(sig, s.serverSignatureCheck) {
				return errors.New("server signature verification failed")
			}
			return nil
		}
	}
	return errors.New("missing server signature in SASLFinal")
}

func hmacSha256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func xorBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	res := make([]byte, n)
	for i := 0; i < n; i++ {
		res[i] = a[i] ^ b[i]
	}
	return res
}

func pbkdf2Sha256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var result []byte
	var blockNum [4]byte

	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(blockNum[:], uint32(block))
		prf.Reset()
		prf.Write(salt)
		prf.Write(blockNum[:])
		u := prf.Sum(nil)
		t := make([]byte, hashLen)
		copy(t, u)

		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
	}
	return result[:keyLen]
}

// ============================================================================
// Client Connection Handler & Bidirectional Relay
// ============================================================================

func handleClientConnection(client net.Conn, cfg *Config) {
	defer client.Close()
	clientRemote := client.RemoteAddr().String()
	log.Printf("[%s] Accepted client connection", clientRemote)

	// Step 1: Read client startup message and parse user & database
	info, err := handleClientHandshake(client)
	if err != nil {
		log.Printf("[%s] Handshake error: %v", clientRemote, err)
		errResp := buildErrorResponse("FATAL", "08P01", err.Error())
		_, _ = client.Write(errResp)
		return
	}
	log.Printf("[%s] Received startup: user=%q database=%q", clientRemote, info.User, info.Database)

	// Step 2: Obtain password for the user via getPassword stub
	password, err := getPassword(info.User, cfg)
	if err != nil {
		log.Printf("[%s] Error retrieving password for user %q: %v", clientRemote, info.User, err)
		errResp := buildErrorResponse("FATAL", "28P01", fmt.Sprintf("failed to get password: %v", err))
		_, _ = client.Write(errResp)
		return
	}

	// Step 3: Connect to target PostgreSQL database
	target, err := connectTarget(cfg)
	if err != nil {
		log.Printf("[%s] Error connecting to target %s: %v", clientRemote, cfg.TargetAddr, err)
		errResp := buildErrorResponse("FATAL", "08006", fmt.Sprintf("cannot connect to backend: %v", err))
		_, _ = client.Write(errResp)
		return
	}
	defer target.Close()

	// Step 4: Authenticate with target PostgreSQL server
	if err := authenticateTarget(target, client, info, password); err != nil {
		log.Printf("[%s] Authentication with target failed: %v", clientRemote, err)
		return
	}
	log.Printf("[%s] Authenticated successfully with target. Starting bidirectional proxying...", clientRemote)

	// Step 5: Transparent bidirectional relay
	relayConnections(client, target)
	log.Printf("[%s] Client connection finished", clientRemote)
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	// If it's a tls.Conn, unwrap it to get the TCP connection
	if tc, ok := conn.(*tls.Conn); ok {
		if cw, ok := tc.NetConn().(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}
}

// relayConnections handles bidirectional streaming between client and backend.
func relayConnections(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Target
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, client)
		if tc, ok := target.(*net.TCPConn); ok {
			closeWrite(tc)
		}
	}()

	// Target -> Client
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, target)
		if tc, ok := client.(*net.TCPConn); ok {
			closeWrite(tc)
		}
	}()

	wg.Wait()
}

// ============================================================================
// Main & CLI Options
// ============================================================================

func normalizeAddress(addr string) string {
	if !strings.Contains(addr, ":") {
		return net.JoinHostPort(addr, "5432")
	}
	return addr
}

func main() {
	listenFlag := flag.String("listen", "127.0.0.1:5432", "Address for proxy to listen on (e.g. 127.0.0.1:5432)")
	targetFlag := flag.String("target", "", "Target PostgreSQL server address (e.g. remote.rds.amazonaws.com:5432)")
	sslModeFlag := flag.String("sslmode", "prefer", "Target SSL mode: 'disable', 'prefer', or 'require'")
	tlsSkipVerifyFlag := flag.Bool("insecure", false, "Skip target TLS certificate verification")
	region := flag.String("region", "eu-west-2", "AWS region")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [target_host:target_port]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	target := *targetFlag
	if target == "" && flag.NArg() > 0 {
		target = flag.Arg(0)
	}

	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: Target PostgreSQL server address is required via -target flag or argument.")
		flag.Usage()
		os.Exit(1)
	}

	target = normalizeAddress(target)
	listen := normalizeAddress(*listenFlag)

	var optFns []func(*config.LoadOptions) error
	if *region != "" {
		optFns = append(optFns, config.WithRegion(*region))
	}

	awscfg, err := config.LoadDefaultConfig(context.Background(), optFns...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load AWS configuration: %v\n", err)
		os.Exit(1)
	}

	cfg := &Config{
		ListenAddr:    listen,
		TargetAddr:    target,
		SSLMode:       strings.ToLower(*sslModeFlag),
		TLSSkipVerify: *tlsSkipVerifyFlag,
		Region:        *region,
		Credentials:   awscfg.Credentials,
	}

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to bind on %s: %v", cfg.ListenAddr, err)
	}
	defer listener.Close()

	log.Printf("RDS PostgreSQL Proxy listening on %s -> forwarding to %s (sslmode=%s)", cfg.ListenAddr, cfg.TargetAddr, cfg.SSLMode)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Received termination signal, shutting down proxy...")
		listener.Close()
		os.Exit(0)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleClientConnection(conn, cfg)
	}
}
