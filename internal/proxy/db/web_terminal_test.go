package dbproxy

import (
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/tursom/turjmp/internal/config"
)

func TestWebTerminalStartsUSQLWithoutSecretInArgv(t *testing.T) {
	dir := t.TempDir()
	argvPath := filepath.Join(dir, "argv.txt")
	fakeUSQL := filepath.Join(dir, "fake-usql")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + shellQuote(argvPath) + "\ncat >/dev/null\n"
	if err := os.WriteFile(fakeUSQL, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	terminal := &WebTerminal{
		cfg: config.Config{Proxy: config.ProxyConfig{DB: config.DBProxyConfig{UsqlPath: fakeUSQL}}},
		api: &testWebTerminalAPI{},
	}
	var raw []byte
	err := runWebTerminalUntilStarted(t, terminal, "token-1", "mysql", func() {
		var readErr error
		raw, readErr = waitForFile(t, argvPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
	})
	if err != nil && !strings.Contains(err.Error(), "status = StatusNormalClosure") {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "target-password") || strings.Contains(string(raw), "mysql://") {
		t.Fatalf("usql argv leaked connection string: %q", string(raw))
	}
}

func TestWebTerminalConnectsUSQLThroughLocalDBProxy(t *testing.T) {
	dir := t.TempDir()
	stdinPath := filepath.Join(dir, "stdin.txt")
	fakeUSQL := filepath.Join(dir, "fake-usql")
	script := "#!/bin/sh\nIFS= read -r line\nprintf '%s\\n' \"$line\" > " + shellQuote(stdinPath) + "\ncat >/dev/null\n"
	if err := os.WriteFile(fakeUSQL, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	terminal := &WebTerminal{
		cfg: config.Config{Proxy: config.ProxyConfig{DB: config.DBProxyConfig{
			PostgresAddr: "0.0.0.0:15437",
			UsqlPath:     fakeUSQL,
		}}},
		api: &testWebTerminalAPI{},
	}
	var raw []byte
	err := runWebTerminalUntilStarted(t, terminal, "token-1", "postgresql", func() {
		var readErr error
		raw, readErr = waitForFile(t, stdinPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
	})
	if err != nil && !strings.Contains(err.Error(), "status = StatusNormalClosure") {
		t.Fatal(err)
	}
	got := strings.TrimSpace(string(raw))
	want := `\connect postgres://web%23token-1@127.0.0.1:15437/postgres?sslmode=disable`
	if got != want {
		t.Fatalf("connect command=%q want %q", got, want)
	}
}

func TestWebTerminalRejectsWhenConnectionLimitReached(t *testing.T) {
	limit := newLimiter(1)
	if !limit.acquire() {
		t.Fatal("failed to pre-acquire db terminal limit")
	}
	defer limit.release()
	terminal := &WebTerminal{
		cfg:   config.Config{},
		api:   &testWebTerminalAPI{},
		limit: limit,
	}
	server := httptest.NewServer(terminal)
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):] + "?token=token-1&protocol=mysql"
	conn, _, err := websocket.Dial(t.Context(), wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	_, _, err = conn.Read(t.Context())
	if err == nil {
		t.Fatal("expected try-again-later close error")
	}
	if got := websocket.CloseStatus(err); got != websocket.StatusTryAgainLater {
		t.Fatalf("close status=%v want %v err=%v", got, websocket.StatusTryAgainLater, err)
	}
}

func TestWebTerminalPreflightsTokenBeforeStartingUSQL(t *testing.T) {
	dir := t.TempDir()
	startedPath := filepath.Join(dir, "started")
	fakeUSQL := filepath.Join(dir, "fake-usql")
	script := "#!/bin/sh\ntouch " + shellQuote(startedPath) + "\ncat >/dev/null\n"
	if err := os.WriteFile(fakeUSQL, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	api := &testWebTerminalAPI{preflightErr: io.EOF}
	terminal := &WebTerminal{
		cfg: config.Config{Proxy: config.ProxyConfig{DB: config.DBProxyConfig{UsqlPath: fakeUSQL}}},
		api: api,
	}
	server := httptest.NewServer(terminal)
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):] + "?token=token-1&protocol=mysql"
	conn, _, err := websocket.Dial(t.Context(), wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	_, _, err = conn.Read(t.Context())
	if got := websocket.CloseStatus(err); got != websocket.StatusPolicyViolation {
		t.Fatalf("close status=%v want %v err=%v", got, websocket.StatusPolicyViolation, err)
	}
	if _, err := os.Stat(startedPath); !os.IsNotExist(err) {
		t.Fatalf("usql should not start after failed preflight, stat err=%v", err)
	}
	if api.preflightProtocol != "mysql" || api.preflightToken != "token-1" {
		t.Fatalf("unexpected preflight token/protocol: %#v", api)
	}
}

func TestUSQLInputGuardBlocksMetaCommandsAcrossChunks(t *testing.T) {
	guard := newUSQLInputGuard()
	got := string(guard.Filter([]byte(`\con`))) + string(guard.Filter([]byte("nect mysql://evil\n")))
	if strings.Contains(got, "mysql://evil\n") {
		t.Fatalf("meta command was not blocked: %q", got)
	}
	if !strings.HasSuffix(got, string([]byte{0x15})) {
		t.Fatalf("missing line-clear control for blocked command: %q", got)
	}
	allowed := string(guard.Filter([]byte("select 1;\n")))
	if allowed != "select 1;\n" {
		t.Fatalf("normal SQL changed: %q", allowed)
	}
}

func TestTerminalOutputScrubberRedactsSecretsAcrossChunks(t *testing.T) {
	s := newTerminalOutputScrubber("mysql://root:target-password@db.internal:3306/app", "target-password")
	first := s.Scrub([]byte("error mysql://root:target-"), false)
	second := s.Scrub([]byte("password@db.internal:3306/app failed"), false)
	third := s.Scrub(nil, true)
	got := string(first) + string(second) + string(third)
	if strings.Contains(got, "target-password") || strings.Contains(got, "mysql://root:") {
		t.Fatalf("secret leaked after scrub: %q", got)
	}
	if !strings.Contains(got, "[redacted]") {
		t.Fatalf("expected redaction marker in %q", got)
	}
}

type testWebTerminalAPI struct {
	preflightToken    string
	preflightProtocol string
	preflightErr      error
}

func (a *testWebTerminalAPI) VerifyConnectionToken(context.Context, string, string, string) (authResult, error) {
	return authResult{}, nil
}

func (a *testWebTerminalAPI) PreflightConnectionToken(_ context.Context, token, _, expectedProtocol string) (authResult, error) {
	a.preflightToken = token
	a.preflightProtocol = expectedProtocol
	return authResult{Target: targetConfig{Protocol: expectedProtocol}}, a.preflightErr
}

func (a *testWebTerminalAPI) CreateSession(context.Context, sessionInfo) (sessionInfo, error) {
	return sessionInfo{}, nil
}

func (a *testWebTerminalAPI) GetSession(context.Context, int64) (sessionInfo, error) {
	return sessionInfo{}, nil
}

func (a *testWebTerminalAPI) FinishSession(context.Context, int64) error {
	return nil
}

func (a *testWebTerminalAPI) Audit(context.Context, int64, string, string, string, string) error {
	return nil
}

func (a *testWebTerminalAPI) GetSetting(context.Context, string) (string, error) {
	return "", nil
}

func runWebTerminalUntilStarted(t *testing.T, terminal *WebTerminal, token, protocol string, afterStart func()) error {
	t.Helper()
	server := httptest.NewServer(terminal)
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):] + "?token=" + token + "&protocol=" + protocol
	conn, _, err := websocket.Dial(t.Context(), wsURL, nil)
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	if afterStart != nil {
		afterStart()
	}
	return conn.Close(websocket.StatusNormalClosure, "")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func waitForFile(t *testing.T, path string) ([]byte, error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		raw, err := os.ReadFile(path)
		if err == nil {
			return raw, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(10 * time.Millisecond)
	}
}
