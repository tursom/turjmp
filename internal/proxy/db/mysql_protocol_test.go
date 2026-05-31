package dbproxy

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestMySQLPacketRoundTrip(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	wantPayload := []byte("hello mysql")
	errCh := make(chan error, 1)
	go func() {
		errCh <- writeMySQLPacket(server, 9, wantPayload)
	}()
	gotPayload, gotSeq, err := readMySQLPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if gotSeq != 9 || !bytes.Equal(gotPayload, wantPayload) {
		t.Fatalf("seq=%d payload=%q", gotSeq, gotPayload)
	}
}

func TestReadMySQLPacketShortPayload(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		_, _ = server.Write([]byte{5, 0, 0, 1, 'a'})
		_ = server.Close()
	}()
	_, _, err := readMySQLPacket(client)
	if err == nil {
		t.Fatal("expected short payload error")
	}
}

func TestWriteHandshake(t *testing.T) {
	payload, seq := capturePacket(t, writeHandshake)
	if seq != 0 {
		t.Fatalf("seq=%d want 0", seq)
	}
	if payload[0] != mysqlProtocolVersion {
		t.Fatalf("protocol=%d", payload[0])
	}
	if !bytes.Contains(payload, []byte(mysqlServerVersion)) {
		t.Fatalf("handshake missing server version: %q", payload)
	}
	if !bytes.Contains(payload, []byte("mysql_native_password")) {
		t.Fatalf("handshake missing auth plugin: %q", payload)
	}
}

func TestParseHandshakeResponse(t *testing.T) {
	tests := []struct {
		name     string
		flags    uint32
		username string
		auth     []byte
		database string
		wantPass string
	}{
		{name: "len encoded auth", flags: mysqlClientPluginAuthLenEnc | mysqlClientConnectWithDB, username: "alice", auth: []byte("token"), database: "app", wantPass: "token"},
		{name: "secure auth", flags: mysqlClientSecureConn, username: "bob#token2", auth: []byte(""), wantPass: ""},
		{name: "old null auth", flags: 0, username: "carol", auth: []byte("legacy"), wantPass: "legacy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHandshakeResponse(handshakeResponsePayload(tt.flags, tt.username, tt.auth, tt.database))
			if err != nil {
				t.Fatal(err)
			}
			if got.Username != tt.username || got.Password != tt.wantPass || got.Database != tt.database {
				t.Fatalf("got %#v", got)
			}
		})
	}
}

func TestParseHandshakeResponseErrors(t *testing.T) {
	truncatedSecureAuth := handshakeResponseHeader(mysqlClientSecureConn, "alice")
	truncatedSecureAuth = append(truncatedSecureAuth, 3, 'x')
	tests := []struct {
		name    string
		payload []byte
		want    string
	}{
		{name: "short", payload: []byte{1, 2, 3}, want: "MySQL 握手响应过短"},
		{name: "missing username terminator", payload: append(make([]byte, 32), []byte("alice")...), want: "缺少 MySQL 用户名"},
		{name: "invalid auth response", payload: truncatedSecureAuth, want: "MySQL 认证响应无效"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseHandshakeResponse(tt.payload)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v want contains %q", err, tt.want)
			}
		})
	}
}

func TestReadAuthResponseBoundaries(t *testing.T) {
	if _, _, ok := readAuthResponse([]byte{0xfc, 1}, 0, mysqlClientPluginAuthLenEnc); ok {
		t.Fatal("expected truncated lenenc auth to fail")
	}
	if _, _, ok := readAuthResponse([]byte{3, 'a'}, 0, mysqlClientSecureConn); ok {
		t.Fatal("expected truncated secure auth to fail")
	}
	if _, _, ok := readAuthResponse([]byte("abc"), 0, 0); ok {
		t.Fatal("expected unterminated old auth to fail")
	}
}

func TestPrintableAuthResponse(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{name: "plain", raw: []byte("token\x00\x00"), want: "token"},
		{name: "empty", raw: []byte("\x00"), want: ""},
		{name: "invalid utf8", raw: []byte{0xff}, want: ""},
		{name: "control", raw: []byte("tok\n"), want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := printableAuthResponse(tt.raw); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestWriteOKEOFAndErrorPackets(t *testing.T) {
	okPayload, okSeq := capturePacket(t, func(conn net.Conn) error {
		return writeOKPacket(conn, 4, 251, 9)
	})
	if okSeq != 4 || okPayload[0] != 0x00 {
		t.Fatalf("unexpected ok packet seq=%d payload=%v", okSeq, okPayload)
	}
	affected, pos, ok := readLenEncInt(okPayload, 1)
	if !ok || affected != 251 {
		t.Fatalf("affected=%d pos=%d ok=%v", affected, pos, ok)
	}
	lastID, _, ok := readLenEncInt(okPayload, pos)
	if !ok || lastID != 9 {
		t.Fatalf("lastID=%d ok=%v", lastID, ok)
	}

	eofPayload, eofSeq := capturePacket(t, func(conn net.Conn) error {
		return writeEOFPacket(conn, 5)
	})
	if eofSeq != 5 || !bytes.Equal(eofPayload, []byte{0xfe, 0, 0, 2, 0}) {
		t.Fatalf("unexpected eof packet seq=%d payload=%v", eofSeq, eofPayload)
	}

	errPayload, errSeq := capturePacket(t, func(conn net.Conn) error {
		return writeErrorPacket(conn, 6, 1045, "denied")
	})
	if errSeq != 6 || errPayload[0] != 0xff || binary.LittleEndian.Uint16(errPayload[1:3]) != 1045 || !bytes.Contains(errPayload, []byte("denied")) {
		t.Fatalf("unexpected err packet seq=%d payload=%v", errSeq, errPayload)
	}
}

func TestLengthEncodedIntegerRoundTrip(t *testing.T) {
	values := []uint64{0, 1, 250, 251, 0xffff, 0x10000, 0xffffff, 0x1000000, 1 << 40}
	for _, value := range values {
		t.Run(string(rune(value%128)), func(t *testing.T) {
			var buf bytes.Buffer
			writeLenEncInt(&buf, value)
			got, pos, ok := readLenEncInt(buf.Bytes(), 0)
			if !ok || got != value || pos != buf.Len() {
				t.Fatalf("got=%d pos=%d ok=%v encoded=%v", got, pos, ok, buf.Bytes())
			}
		})
	}
	for _, raw := range [][]byte{{0xfc, 1}, {0xfd, 1, 2}, {0xfe, 1, 2, 3}} {
		if _, _, ok := readLenEncInt(raw, 0); ok {
			t.Fatalf("expected truncated lenenc to fail for %v", raw)
		}
	}
}

func TestRowPacketAndValueString(t *testing.T) {
	ts := time.Date(2026, 5, 29, 12, 34, 56, 123456000, time.UTC)
	packet := rowPacket([]any{[]byte("abc"), nil, ts, 42})
	value, pos, ok := readLenEncInt(packet, 0)
	if !ok || value != 3 || string(packet[pos:pos+3]) != "abc" {
		t.Fatalf("bad first column packet=%v", packet)
	}
	if packet[pos+3] != 0xfb {
		t.Fatalf("expected null marker, packet=%v", packet)
	}
	if got := mysqlValueString(ts); got != "2026-05-29 12:34:56.123456" {
		t.Fatalf("time string got %q", got)
	}
	if got := mysqlValueString(42); got != "42" {
		t.Fatalf("int string got %q", got)
	}
}

func TestColumnDefinitionPacket(t *testing.T) {
	packet := columnDefinitionPacket("app", "users", "id", mysqlTypeLong)
	if !bytes.Contains(packet, []byte("def")) || !bytes.Contains(packet, []byte("users")) || !bytes.Contains(packet, []byte("id")) {
		t.Fatalf("column definition missing expected strings: %v", packet)
	}
	if !bytes.Contains(packet, []byte{mysqlTypeLong}) {
		t.Fatalf("column definition missing type byte: %v", packet)
	}
}

func TestMySQLColumnType(t *testing.T) {
	tests := map[string]byte{
		"INT":       mysqlTypeLong,
		"integer":   mysqlTypeLong,
		"BIGINT":    mysqlTypeLongLong,
		"FLOAT":     mysqlTypeFloat,
		"DOUBLE":    mysqlTypeDouble,
		"DECIMAL":   mysqlTypeDecimal,
		"DATE":      mysqlTypeDate,
		"TIME":      mysqlTypeTime,
		"DATETIME":  mysqlTypeDateTime,
		"TIMESTAMP": mysqlTypeTimestamp,
		"JSON":      mysqlTypeJSON,
		"VARCHAR":   mysqlTypeVarString,
	}
	for dbType, want := range tests {
		t.Run(dbType, func(t *testing.T) {
			if got := mysqlColumnType(dbType); got != want {
				t.Fatalf("got 0x%x want 0x%x", got, want)
			}
		})
	}
}

func TestIsResultQuery(t *testing.T) {
	tests := map[string]bool{
		"":                 false,
		"   ":              false,
		"select 1":         true,
		" SHOW DATABASES":  true,
		"describe users":   true,
		"DESC users":       true,
		"explain select 1": true,
		"with cte as (select 1) select * from cte": true,
		"call proc()":              true,
		"insert into t values (1)": false,
		"update t set a=1":         false,
	}
	for query, want := range tests {
		t.Run(query, func(t *testing.T) {
			if got := isResultQuery(query); got != want {
				t.Fatalf("got %v want %v", got, want)
			}
		})
	}
}

func TestQuoteAndStrconvHelpers(t *testing.T) {
	if got := quoteMySQLIdent("a`b"); got != "`a``b`" {
		t.Fatalf("got %q", got)
	}
	if got := strconvUint64(-1); got != 0 {
		t.Fatalf("negative uint got %d", got)
	}
	if got := strconvUint64(42); got != 42 {
		t.Fatalf("positive uint got %d", got)
	}
	if got := strconvInt64("bad"); got != 0 {
		t.Fatalf("bad int got %d", got)
	}
	if got := strconvInt64("123"); got != 123 {
		t.Fatalf("int got %d", got)
	}
}

func TestWriteResultSet(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT 1 AS num, 'alice' AS name, NULL AS missing`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	errCh := make(chan error, 1)
	var written int64
	go func() {
		var err error
		written, err = writeResultSet(server, rows)
		errCh <- err
	}()

	payload, seq, err := readMySQLPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 1 || len(payload) != 1 || payload[0] != 3 {
		t.Fatalf("bad result header seq=%d payload=%v", seq, payload)
	}
	for wantSeq := byte(2); wantSeq <= 4; wantSeq++ {
		payload, seq, err = readMySQLPacket(client)
		if err != nil {
			t.Fatal(err)
		}
		if seq != wantSeq || !bytes.Contains(payload, []byte("def")) {
			t.Fatalf("bad column seq=%d payload=%v", seq, payload)
		}
	}
	payload, seq, err = readMySQLPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 5 || payload[0] != 0xfe {
		t.Fatalf("bad column eof seq=%d payload=%v", seq, payload)
	}
	payload, seq, err = readMySQLPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 6 || !bytes.Contains(payload, []byte("alice")) || !bytes.Contains(payload, []byte{0xfb}) {
		t.Fatalf("bad row seq=%d payload=%v", seq, payload)
	}
	payload, seq, err = readMySQLPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 7 || payload[0] != 0xfe {
		t.Fatalf("bad row eof seq=%d payload=%v", seq, payload)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if written != 1 {
		t.Fatalf("written=%d want 1", written)
	}
}

func handshakeResponsePayload(flags uint32, username string, auth []byte, database string) []byte {
	buf := bytes.NewBuffer(handshakeResponseHeader(flags, username))
	switch {
	case flags&mysqlClientPluginAuthLenEnc != 0:
		writeLenEncInt(buf, uint64(len(auth)))
		buf.Write(auth)
	case flags&mysqlClientSecureConn != 0:
		if len(auth) > 255 {
			buf.WriteByte(255)
		} else {
			buf.WriteByte(byte(len(auth)))
		}
		buf.Write(auth)
	default:
		buf.Write(auth)
		buf.WriteByte(0)
	}
	if flags&mysqlClientConnectWithDB != 0 {
		buf.WriteString(database)
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

func handshakeResponseHeader(flags uint32, username string) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, flags)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(mysqlMaxPacketSize))
	buf.WriteByte(33)
	buf.Write(make([]byte, 23))
	buf.WriteString(username)
	buf.WriteByte(0)
	return buf.Bytes()
}

func capturePacket(t *testing.T, write func(net.Conn) error) ([]byte, byte) {
	t.Helper()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- write(server)
	}()
	payload, seq, err := readMySQLPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil && !strings.Contains(err.Error(), io.ErrClosedPipe.Error()) {
		t.Fatal(err)
	}
	return payload, seq
}
