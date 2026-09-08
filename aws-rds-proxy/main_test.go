package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"
)

// TestPBKDF2Sha256 verifies the PBKDF2-HMAC-SHA256 implementation against RFC 6070 test vectors.
func TestPBKDF2Sha256(t *testing.T) {
	// RFC 6070 test vector 1:
	// P = "password", S = "salt", c = 1, dkLen = 32
	// DK = 120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b
	res1 := pbkdf2Sha256([]byte("password"), []byte("salt"), 1, 32)
	expected1 := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if hex.EncodeToString(res1) != expected1 {
		t.Fatalf("RFC 6070 vector 1 failed: got %x, want %s", res1, expected1)
	}

	// RFC 6070 test vector 2:
	// P = "password", S = "salt", c = 2, dkLen = 32
	// DK = ae4d0c95af6b4613c76e4764b8ac3a7ee2e69cedc6b3d8f4aac002cd2436d2fe
	res2 := pbkdf2Sha256([]byte("password"), []byte("salt"), 2, 32)
	expected2 := "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
	if hex.EncodeToString(res2) != expected2 {
		t.Fatalf("RFC 6070 vector 2 failed: got %x, want %s", res2, expected2)
	}
}

// TestComputeMD5Password verifies PostgreSQL MD5 password hashing.
func TestComputeMD5Password(t *testing.T) {
	salt := []byte{1, 2, 3, 4}
	res := computeMD5Password("secret", "myuser", salt)
	if !strings.HasPrefix(res, "md5") {
		t.Fatalf("expected md5 prefix, got %s", res)
	}
	if len(res) != 35 { // "md5" + 32 hex characters
		t.Fatalf("expected length 35, got %d", len(res))
	}

	// Verify manual calculation
	h1 := md5.Sum([]byte("secretmyuser"))
	h1Hex := hex.EncodeToString(h1[:])
	h2 := md5.New()
	h2.Write([]byte(h1Hex))
	h2.Write(salt)
	expected := "md5" + hex.EncodeToString(h2.Sum(nil))

	if res != expected {
		t.Fatalf("mismatch: got %s, want %s", res, expected)
	}
}

// TestParseStartupParameters tests parameter extraction from startup packet.
func TestParseStartupParameters(t *testing.T) {
	// "user\0postgres\0database\0mydb\0application_name\0psql\0\0"
	var buf bytes.Buffer
	buf.WriteString("user\x00postgres\x00")
	buf.WriteString("database\x00mydb\x00")
	buf.WriteString("application_name\x00psql\x00")
	buf.WriteByte(0)

	params, err := parseStartupParameters(buf.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if params["user"] != "postgres" {
		t.Errorf("expected user postgres, got %q", params["user"])
	}
	if params["database"] != "mydb" {
		t.Errorf("expected database mydb, got %q", params["database"])
	}
	if params["application_name"] != "psql" {
		t.Errorf("expected app name psql, got %q", params["application_name"])
	}
}

// TestBuildStartupMessage verifies the structure of built startup messages.
func TestBuildStartupMessage(t *testing.T) {
	params := map[string]string{
		"user":     "alice",
		"database": "alicedb",
	}
	msg := buildStartupMessage(params)
	if len(msg) < 8 {
		t.Fatalf("message too short: %d", len(msg))
	}
	length := binary.BigEndian.Uint32(msg[0:4])
	if int(length) != len(msg) {
		t.Fatalf("length prefix %d does not match slice len %d", length, len(msg))
	}
	proto := binary.BigEndian.Uint32(msg[4:8])
	if proto != protocolVersion3 {
		t.Fatalf("proto %d does not match 196608", proto)
	}

	parsed, err := parseStartupParameters(msg[8:])
	if err != nil {
		t.Fatalf("failed to parse built startup message: %v", err)
	}
	if parsed["user"] != "alice" || parsed["database"] != "alicedb" {
		t.Fatalf("parsed params mismatch: %+v", parsed)
	}
}

// TestProxyEndToEndCleartext tests end-to-end proxying with cleartext auth.
func TestProxyEndToEndCleartext(t *testing.T) {
	// 1. Start mock backend
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen mock backend: %v", err)
	}
	defer backendListener.Close()
	backendAddr := backendListener.Addr().String()

	go func() {
		conn, err := backendListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read StartupMessage
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		msgLen := binary.BigEndian.Uint32(lenBuf[:])
		body := make([]byte, msgLen-4)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}

		// Send AuthRequestCleartext ('R', len 8, type 3)
		var authReq [9]byte
		authReq[0] = 'R'
		binary.BigEndian.PutUint32(authReq[1:5], 8)
		binary.BigEndian.PutUint32(authReq[5:9], authTypeCleartextPassword)
		conn.Write(authReq[:])

		// Read PasswordMessage ('p', len, "password\0")
		var pHead [5]byte
		io.ReadFull(conn, pHead[:])
		pLen := binary.BigEndian.Uint32(pHead[1:5])
		passPayload := make([]byte, pLen-4)
		io.ReadFull(conn, passPayload)

		// Send AuthenticationOk ('R', len 8, type 0)
		var authOk [9]byte
		authOk[0] = 'R'
		binary.BigEndian.PutUint32(authOk[1:5], 8)
		binary.BigEndian.PutUint32(authOk[5:9], authTypeOk)
		conn.Write(authOk[:])

		// Send ReadyForQuery ('Z', len 5, 'I')
		conn.Write([]byte{'Z', 0, 0, 0, 5, 'I'})

		// Read Query ('Q', len 10, "SELECT 1\0")
		var qHead [5]byte
		io.ReadFull(conn, qHead[:])
		qLen := binary.BigEndian.Uint32(qHead[1:5])
		qPayload := make([]byte, qLen-4)
		io.ReadFull(conn, qPayload)

		// Send CommandComplete ('C', len 10, "SELECT 1\0")
		conn.Write([]byte{'C', 0, 0, 0, 13, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0})
		// Send ReadyForQuery ('Z')
		conn.Write([]byte{'Z', 0, 0, 0, 5, 'I'})
	}()

	// 2. Start proxy
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen proxy: %v", err)
	}
	defer proxyListener.Close()
	proxyAddr := proxyListener.Addr().String()

	cfg := &Config{
		ListenAddr: proxyAddr,
		TargetAddr: backendAddr,
		SSLMode:    "disable",
	}

	go func() {
		conn, err := proxyListener.Accept()
		if err != nil {
			return
		}
		handleClientConnection(conn, cfg)
	}()

	// 3. Connect client to proxy
	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	defer client.Close()

	// 3a. Send SSLRequest
	var sslReq [8]byte
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], sslRequestCode)
	client.Write(sslReq[:])

	var sslResp [1]byte
	io.ReadFull(client, sslResp[:])
	if sslResp[0] != sslNotAllowed {
		t.Fatalf("expected 'N' for SSLRequest, got %c", sslResp[0])
	}

	// 3b. Send StartupMessage
	startup := buildStartupMessage(map[string]string{
		"user":     "myuser",
		"database": "mydb",
	})
	client.Write(startup)

	// 3c. Expect AuthenticationOk
	var authOkResp [9]byte
	io.ReadFull(client, authOkResp[:])
	if authOkResp[0] != 'R' {
		t.Fatalf("expected 'R', got %c", authOkResp[0])
	}
	if binary.BigEndian.Uint32(authOkResp[5:9]) != authTypeOk {
		t.Fatalf("expected AuthOk, got %d", binary.BigEndian.Uint32(authOkResp[5:9]))
	}

	// 3d. Expect ReadyForQuery
	var rfq [6]byte
	io.ReadFull(client, rfq[:])
	if rfq[0] != 'Z' {
		t.Fatalf("expected 'Z', got %c", rfq[0])
	}

	// 3e. Send Query
	query := "SELECT 1\x00"
	var qBuf bytes.Buffer
	qBuf.WriteByte('Q')
	var qLen [4]byte
	binary.BigEndian.PutUint32(qLen[:], uint32(4+len(query)))
	qBuf.Write(qLen[:])
	qBuf.WriteString(query)
	client.Write(qBuf.Bytes())

	// 3f. Expect CommandComplete
	var ccHead [5]byte
	io.ReadFull(client, ccHead[:])
	if ccHead[0] != 'C' {
		t.Fatalf("expected 'C', got %c", ccHead[0])
	}
	ccLen := binary.BigEndian.Uint32(ccHead[1:5])
	ccBody := make([]byte, ccLen-4)
	io.ReadFull(client, ccBody)
	if string(ccBody) != "SELECT 1\x00" {
		t.Fatalf("unexpected query response: %s", string(ccBody))
	}
}

// TestProxyEndToEndMD5 tests end-to-end proxying with MD5 auth challenge from backend.
func TestProxyEndToEndMD5(t *testing.T) {
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen mock backend: %v", err)
	}
	defer backendListener.Close()
	backendAddr := backendListener.Addr().String()

	salt := []byte{0x12, 0x34, 0x56, 0x78}

	go func() {
		conn, err := backendListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read StartupMessage
		var lenBuf [4]byte
		io.ReadFull(conn, lenBuf[:])
		msgLen := binary.BigEndian.Uint32(lenBuf[:])
		body := make([]byte, msgLen-4)
		io.ReadFull(conn, body)

		// Send AuthRequestMD5 ('R', len 12, type 5, salt 4 bytes)
		var authReq [13]byte
		authReq[0] = 'R'
		binary.BigEndian.PutUint32(authReq[1:5], 12)
		binary.BigEndian.PutUint32(authReq[5:9], authTypeMD5Password)
		copy(authReq[9:13], salt)
		conn.Write(authReq[:])

		// Read PasswordMessage ('p')
		var pHead [5]byte
		io.ReadFull(conn, pHead[:])
		pLen := binary.BigEndian.Uint32(pHead[1:5])
		passPayload := make([]byte, pLen-4)
		io.ReadFull(conn, passPayload)

		// Verify MD5 token
		expectedToken := computeMD5Password("password", "md5user", salt) + "\x00"
		if string(passPayload) != expectedToken {
			t.Errorf("MD5 token mismatch: got %q, want %q", string(passPayload), expectedToken)
		}

		// Send AuthenticationOk ('R', len 8, type 0)
		var authOk [9]byte
		authOk[0] = 'R'
		binary.BigEndian.PutUint32(authOk[1:5], 8)
		binary.BigEndian.PutUint32(authOk[5:9], authTypeOk)
		conn.Write(authOk[:])

		// Send ReadyForQuery ('Z', len 5, 'I')
		conn.Write([]byte{'Z', 0, 0, 0, 5, 'I'})
	}()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen proxy: %v", err)
	}
	defer proxyListener.Close()
	proxyAddr := proxyListener.Addr().String()

	cfg := &Config{
		ListenAddr: proxyAddr,
		TargetAddr: backendAddr,
		SSLMode:    "disable",
	}

	go func() {
		conn, err := proxyListener.Accept()
		if err != nil {
			return
		}
		handleClientConnection(conn, cfg)
	}()

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	defer client.Close()

	// Send StartupMessage
	startup := buildStartupMessage(map[string]string{
		"user":     "md5user",
		"database": "mydb",
	})
	client.Write(startup)

	// Expect AuthenticationOk
	var authOkResp [9]byte
	io.ReadFull(client, authOkResp[:])
	if authOkResp[0] != 'R' || binary.BigEndian.Uint32(authOkResp[5:9]) != authTypeOk {
		t.Fatalf("expected AuthOk, got %v", authOkResp)
	}

	// Expect ReadyForQuery
	var rfq [6]byte
	io.ReadFull(client, rfq[:])
	if rfq[0] != 'Z' {
		t.Fatalf("expected 'Z', got %c", rfq[0])
	}
}

// TestProxyEndToEndSCRAM tests end-to-end proxying with SCRAM-SHA-256 auth.
func TestProxyEndToEndSCRAM(t *testing.T) {
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen mock backend: %v", err)
	}
	defer backendListener.Close()
	backendAddr := backendListener.Addr().String()

	go func() {
		conn, err := backendListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read StartupMessage
		var lenBuf [4]byte
		io.ReadFull(conn, lenBuf[:])
		msgLen := binary.BigEndian.Uint32(lenBuf[:])
		body := make([]byte, msgLen-4)
		io.ReadFull(conn, body)

		// 1. Send AuthenticationSASL ('R', len, type 10, "SCRAM-SHA-256\0\0")
		mech := "SCRAM-SHA-256\x00\x00"
		var saslReq bytes.Buffer
		saslReq.WriteByte('R')
		binary.Write(&saslReq, binary.BigEndian, uint32(4+4+len(mech)))
		binary.Write(&saslReq, binary.BigEndian, authTypeSASL)
		saslReq.WriteString(mech)
		conn.Write(saslReq.Bytes())

		// 2. Read SASLInitialResponse ('p')
		var pHead [5]byte
		io.ReadFull(conn, pHead[:])
		pLen := binary.BigEndian.Uint32(pHead[1:5])
		pBody := make([]byte, pLen-4)
		io.ReadFull(conn, pBody)

		// Parse client first message
		// Mech null terminated, then int32 client message len, then client message
		nullIdx := bytes.IndexByte(pBody, 0)
		clientMsgLen := binary.BigEndian.Uint32(pBody[nullIdx+1 : nullIdx+5])
		clientMsg := string(pBody[nullIdx+5 : nullIdx+5+int(clientMsgLen)])
		// e.g. "n,,n=,r=clientNonce"
		parts := strings.Split(clientMsg, ",")
		var clientNonce string
		for _, part := range parts {
			if strings.HasPrefix(part, "r=") {
				clientNonce = part[2:]
			}
		}

		serverNonce := clientNonce + "SERVERNONCE123456"
		salt := []byte("randomsalt123456")
		saltB64 := base64.StdEncoding.EncodeToString(salt)
		iterations := 4096
		serverFirst := "r=" + serverNonce + ",s=" + saltB64 + ",i=4096"

		// 3. Send AuthenticationSASLContinue ('R', len, type 11, serverFirst)
		var contReq bytes.Buffer
		contReq.WriteByte('R')
		binary.Write(&contReq, binary.BigEndian, uint32(4+4+len(serverFirst)))
		binary.Write(&contReq, binary.BigEndian, authTypeSASLContinue)
		contReq.WriteString(serverFirst)
		conn.Write(contReq.Bytes())

		// 4. Read SASLResponse ('p')
		io.ReadFull(conn, pHead[:])
		pLen = binary.BigEndian.Uint32(pHead[1:5])
		clientFinal := make([]byte, pLen-4)
		io.ReadFull(conn, clientFinal)

		// Compute expected server signature
		channelBinding := "c=biws"
		clientFinalWithoutProof := channelBinding + ",r=" + serverNonce
		clientFirstBare := "n=,r=" + clientNonce
		authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof
		saltedPassword := pbkdf2Sha256([]byte("password"), salt, iterations, 32)
		serverKey := hmacSha256(saltedPassword, []byte("Server Key"))
		serverSig := hmacSha256(serverKey, []byte(authMessage))
		serverFinal := "v=" + base64.StdEncoding.EncodeToString(serverSig)

		// 5. Send AuthenticationSASLFinal ('R', len, type 12, serverFinal)
		var finReq bytes.Buffer
		finReq.WriteByte('R')
		binary.Write(&finReq, binary.BigEndian, uint32(4+4+len(serverFinal)))
		binary.Write(&finReq, binary.BigEndian, authTypeSASLFinal)
		finReq.WriteString(serverFinal)
		conn.Write(finReq.Bytes())

		// 6. Send AuthenticationOk ('R', len 8, type 0)
		var authOk [9]byte
		authOk[0] = 'R'
		binary.BigEndian.PutUint32(authOk[1:5], 8)
		binary.BigEndian.PutUint32(authOk[5:9], authTypeOk)
		conn.Write(authOk[:])

		// 7. Send ReadyForQuery ('Z')
		conn.Write([]byte{'Z', 0, 0, 0, 5, 'I'})
	}()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen proxy: %v", err)
	}
	defer proxyListener.Close()
	proxyAddr := proxyListener.Addr().String()

	cfg := &Config{
		ListenAddr: proxyAddr,
		TargetAddr: backendAddr,
		SSLMode:    "disable",
	}

	go func() {
		conn, err := proxyListener.Accept()
		if err != nil {
			return
		}
		handleClientConnection(conn, cfg)
	}()

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	defer client.Close()

	// Send StartupMessage
	startup := buildStartupMessage(map[string]string{
		"user":     "scramuser",
		"database": "mydb",
	})
	client.Write(startup)

	// Expect AuthenticationOk
	var authOkResp [9]byte
	io.ReadFull(client, authOkResp[:])
	if authOkResp[0] != 'R' || binary.BigEndian.Uint32(authOkResp[5:9]) != authTypeOk {
		t.Fatalf("expected AuthOk, got %v", authOkResp)
	}

	// Expect ReadyForQuery
	var rfq [6]byte
	io.ReadFull(client, rfq[:])
	if rfq[0] != 'Z' {
		t.Fatalf("expected 'Z', got %c", rfq[0])
	}
}

// TestProxyGSSENCRequest verifies that GSS encryption requests are rejected with 'N'.
func TestProxyGSSENCRequest(t *testing.T) {
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen mock backend: %v", err)
	}
	defer backendListener.Close()
	backendAddr := backendListener.Addr().String()

	go func() {
		conn, err := backendListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read StartupMessage
		var lenBuf [4]byte
		io.ReadFull(conn, lenBuf[:])
		msgLen := binary.BigEndian.Uint32(lenBuf[:])
		body := make([]byte, msgLen-4)
		io.ReadFull(conn, body)

		// Send AuthenticationOk
		var authOk [9]byte
		authOk[0] = 'R'
		binary.BigEndian.PutUint32(authOk[1:5], 8)
		binary.BigEndian.PutUint32(authOk[5:9], authTypeOk)
		conn.Write(authOk[:])
		conn.Write([]byte{'Z', 0, 0, 0, 5, 'I'})
	}()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen proxy: %v", err)
	}
	defer proxyListener.Close()
	proxyAddr := proxyListener.Addr().String()

	cfg := &Config{
		ListenAddr: proxyAddr,
		TargetAddr: backendAddr,
		SSLMode:    "disable",
	}

	go func() {
		conn, err := proxyListener.Accept()
		if err != nil {
			return
		}
		handleClientConnection(conn, cfg)
	}()

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	defer client.Close()

	// Send GSSENCRequest
	var gssReq [8]byte
	binary.BigEndian.PutUint32(gssReq[0:4], 8)
	binary.BigEndian.PutUint32(gssReq[4:8], gssEncRequestCode)
	client.Write(gssReq[:])

	var gssResp [1]byte
	io.ReadFull(client, gssResp[:])
	if gssResp[0] != sslNotAllowed {
		t.Fatalf("expected 'N' for GSSENCRequest, got %c", gssResp[0])
	}

	// Send StartupMessage
	startup := buildStartupMessage(map[string]string{
		"user":     "gssuser",
		"database": "gssdb",
	})
	client.Write(startup)

	var authOkResp [9]byte
	io.ReadFull(client, authOkResp[:])
	if authOkResp[0] != 'R' || binary.BigEndian.Uint32(authOkResp[5:9]) != authTypeOk {
		t.Fatalf("expected AuthOk, got %v", authOkResp)
	}
}

// TestProxyBackendErrorResponse verifies that ErrorResponses from backend are relayed to the client.
func TestProxyBackendErrorResponse(t *testing.T) {
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen mock backend: %v", err)
	}
	defer backendListener.Close()
	backendAddr := backendListener.Addr().String()

	go func() {
		conn, err := backendListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read StartupMessage
		var lenBuf [4]byte
		io.ReadFull(conn, lenBuf[:])
		msgLen := binary.BigEndian.Uint32(lenBuf[:])
		body := make([]byte, msgLen-4)
		io.ReadFull(conn, body)

		// Send ErrorResponse ('E')
		errPacket := buildErrorResponse("FATAL", "28P01", "password authentication failed for user testuser")
		conn.Write(errPacket)
	}()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen proxy: %v", err)
	}
	defer proxyListener.Close()
	proxyAddr := proxyListener.Addr().String()

	cfg := &Config{
		ListenAddr: proxyAddr,
		TargetAddr: backendAddr,
		SSLMode:    "disable",
	}

	go func() {
		conn, err := proxyListener.Accept()
		if err != nil {
			return
		}
		handleClientConnection(conn, cfg)
	}()

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	defer client.Close()

	startup := buildStartupMessage(map[string]string{
		"user":     "testuser",
		"database": "testdb",
	})
	client.Write(startup)

	// Expect ErrorResponse ('E')
	var errHead [5]byte
	io.ReadFull(client, errHead[:])
	if errHead[0] != 'E' {
		t.Fatalf("expected ErrorResponse 'E', got %c", errHead[0])
	}
	eLen := binary.BigEndian.Uint32(errHead[1:5])
	eBody := make([]byte, eLen-4)
	io.ReadFull(client, eBody)
	if !strings.Contains(string(eBody), "password authentication failed") {
		t.Fatalf("expected error message in payload, got %q", string(eBody))
	}
}

