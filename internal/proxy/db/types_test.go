package dbproxy

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestExtractConnectionToken(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		want     string
	}{
		{name: "password wins without hash", username: "user-token", password: "pass-token", want: "pass-token"},
		{name: "username fallback", username: "user-token", password: "", want: "user-token"},
		{name: "username hash format", username: "realuser#token-123", password: "", want: "token-123"},
		// 用户名#token 优先于真实密码：验证优先级反转 ——
		// 用户名中的 #token 优先于真实数据库密码，确保原生客户端
		// （mysql、psql 等）可将令牌放在登录用户名中传递。
		{name: "username hash wins over real password", username: "realuser#token-123", password: "real-db-password", want: "token-123"},
		{name: "password hash format", username: "realuser", password: "ignored#token-456", want: "token-456"},
		{name: "trim spaces", username: "  token-with-space  ", password: "", want: "token-with-space"},
		{name: "trim null bytes", username: "\x00token\x00", password: "", want: "token"},
		{name: "empty hash suffix falls back to raw candidate", username: "realuser#", password: "", want: "realuser#"},
		{name: "all empty", username: "", password: " \x00 ", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractConnectionToken(tt.username, tt.password); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestParseSettingString(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		fallback string
		want     string
	}{
		{name: "blank", raw: " ", fallback: "fallback", want: "fallback"},
		{name: "json string", raw: `"./recordings"`, fallback: "fallback", want: "./recordings"},
		{name: "empty json string", raw: `""`, fallback: "fallback", want: "fallback"},
		{name: "plain", raw: "plain", fallback: "fallback", want: "plain"},
		{name: "quoted fallback parser", raw: `"plain`, fallback: "fallback", want: "plain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseSettingString(tt.raw, tt.fallback); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestParseSettingInt(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		fallback int64
		want     int64
	}{
		{name: "blank", raw: "", fallback: 42, want: 42},
		{name: "json number", raw: "1800", fallback: 42, want: 1800},
		{name: "quoted number", raw: `"50"`, fallback: 42, want: 50},
		{name: "invalid", raw: "abc", fallback: 42, want: 42},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseSettingInt(tt.raw, tt.fallback); got != tt.want {
				t.Fatalf("got %d want %d", got, tt.want)
			}
		})
	}
}

func TestProtocolDefaultPortAndTargetPort(t *testing.T) {
	tests := []struct {
		name   string
		target targetConfig
		want   int
	}{
		{name: "explicit wins", target: targetConfig{Protocol: "mysql", Port: 13306}, want: 13306},
		{name: "mysql default", target: targetConfig{Protocol: "mysql"}, want: 3306},
		{name: "postgres default", target: targetConfig{Protocol: "postgres"}, want: 5432},
		{name: "postgresql default", target: targetConfig{Protocol: "postgresql"}, want: 5432},
		{name: "unknown", target: targetConfig{Protocol: "oracle"}, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := targetPort(tt.target); got != tt.want {
				t.Fatalf("got %d want %d", got, tt.want)
			}
		})
	}
}

func TestSafeRemoteAddr(t *testing.T) {
	if got := safeRemoteAddr(nil); got != "" {
		t.Fatalf("nil addr got %q", got)
	}
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	if got := safeRemoteAddr(addr); got != "127.0.0.1:1234" {
		t.Fatalf("got %q", got)
	}
}

func TestNewSQLAuditDetail(t *testing.T) {
	got := newSQLAuditDetail(7, "mysql", "select 1", 15*time.Millisecond, 1, errors.New("boom"))
	var detail sqlAuditDetail
	if err := json.Unmarshal([]byte(got), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.SessionID != 7 || detail.Protocol != "mysql" || detail.SQL != "select 1" || detail.DurationMS != 15 || detail.RowsAffected != 1 || detail.Error != "boom" {
		t.Fatalf("unexpected audit detail: %#v", detail)
	}
	if strings.Contains(newSQLAuditDetail(1, "mysql", "select 1", 0, 0, nil), `"error"`) {
		t.Fatal("did not expect empty error field")
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(1)
	if !l.acquire() {
		t.Fatal("expected first acquire to succeed")
	}
	if l.acquire() {
		t.Fatal("expected second acquire to fail")
	}
	l.release()
	l.release()
	if !l.acquire() {
		t.Fatal("expected acquire after release to succeed")
	}
}

func TestBuildMySQLDSN(t *testing.T) {
	got := buildMySQLDSN(authResult{
		Target: targetConfig{Address: "db.internal", Port: 3307, Protocol: "mysql"},
		Account: targetAccount{
			Username: "alice",
			Secret:   "p@ss:word",
			DBName:   "test/db",
		},
	}, 3*time.Second)
	if !strings.Contains(got, "alice:p@ss:word@tcp(db.internal:3307)/test%2Fdb") {
		t.Fatalf("unexpected mysql dsn: %s", got)
	}
	for _, part := range []string{"timeout=3s", "readTimeout=3s", "writeTimeout=3s", "parseTime=true", "charset=utf8mb4"} {
		if !strings.Contains(got, part) {
			t.Fatalf("dsn %q missing %q", got, part)
		}
	}
}

func TestBuildPostgresDSN(t *testing.T) {
	got := buildPostgresDSN(authResult{
		Target: targetConfig{Address: "pg.internal", Protocol: "postgresql"},
		Account: targetAccount{
			Username: "bob",
			Secret:   "s ecret",
			DBName:   "app/db",
		},
	}, 2500*time.Millisecond)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "postgres" || u.Host != "pg.internal:5432" || normalizeDSNForTest(u.Path) != "/app/db" {
		t.Fatalf("unexpected postgres dsn: %s", got)
	}
	if user := u.User.Username(); user != "bob" {
		t.Fatalf("user=%q", user)
	}
	if password, _ := u.User.Password(); password != "s ecret" {
		t.Fatalf("password=%q", password)
	}
	query := u.Query()
	for key, want := range map[string]string{
		"sslmode":          "disable",
		"connect_timeout":  "2",
		"application_name": "turjmp",
	} {
		if got := query.Get(key); got != want {
			t.Fatalf("query %s got %q want %q in %s", key, got, want, got)
		}
	}
}

func TestBuildUSQLDSN(t *testing.T) {
	tests := []struct {
		name     string
		auth     authResult
		wantURL  string
		wantErr  string
		wantParm map[string]string
	}{
		{
			name: "mysql",
			auth: authResult{
				Target:  targetConfig{Address: "127.0.0.1", Port: 3306, Protocol: "mysql"},
				Account: targetAccount{Username: "alice", Secret: "pw", DBName: "testdb"},
			},
			wantURL: "mysql://alice:pw@127.0.0.1:3306/testdb",
		},
		{
			name: "postgres default port",
			auth: authResult{
				Target:  targetConfig{Address: "pg.internal", Protocol: "postgresql"},
				Account: targetAccount{Username: "bob", Secret: "secret", DBName: "app"},
			},
			wantURL:  "postgres://bob:secret@pg.internal:5432/app?sslmode=disable",
			wantParm: map[string]string{"sslmode": "disable"},
		},
		{
			name:    "unsupported",
			auth:    authResult{Target: targetConfig{Protocol: "oracle"}},
			wantErr: "unsupported db terminal protocol",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildUSQLDSN(tt.auth)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err=%v want contains %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.wantURL {
				t.Fatalf("got %q want %q", got, tt.wantURL)
			}
			u, err := url.Parse(got)
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range tt.wantParm {
				if got := u.Query().Get(k); got != v {
					t.Fatalf("query %s got %q want %q", k, got, v)
				}
			}
		})
	}
}

func TestFormatURLDSNWithoutUserAndEscaping(t *testing.T) {
	got := formatURLDSN("mysql", "", "", "db.internal", 3306, "space db", nil)
	if got != "mysql://db.internal:3306/space%20db" {
		t.Fatalf("unexpected dsn: %s", got)
	}
	if normalizeDSNForTest("mysql://h/test%2Fdb") != "mysql://h/test/db" {
		t.Fatal("normalizeDSNForTest did not restore encoded slash")
	}
}

func TestParseResizeMessage(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		ok   bool
		rows int
		cols int
	}{
		{name: "valid", raw: `{"type":"resize","rows":30,"cols":120}`, ok: true, rows: 30, cols: 120},
		{name: "bad json", raw: `{`, ok: false},
		{name: "wrong type", raw: `{"type":"input","rows":30,"cols":120}`, ok: false},
		{name: "zero rows", raw: `{"type":"resize","rows":0,"cols":120}`, ok: false},
		{name: "zero cols", raw: `{"type":"resize","rows":30,"cols":0}`, ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, ok := parseResizeMessage([]byte(tt.raw))
			if ok != tt.ok {
				t.Fatalf("ok=%v want %v", ok, tt.ok)
			}
			if ok && (msg.Rows != tt.rows || msg.Cols != tt.cols) {
				t.Fatalf("unexpected resize parse: %#v", msg)
			}
		})
	}
}
