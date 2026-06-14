package sshproxy

import (
	"context"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/coder/websocket"
	gossh "golang.org/x/crypto/ssh"

	"github.com/tursom/turjmp/internal/config"
)

func TestWebTerminalRejectsNonSSHConnectionToken(t *testing.T) {
	api := &testWebTerminalAPI{
		auth: targetAuthResult{
			Target: targetConfig{Address: "db.internal", Port: 3306, Protocol: "mysql"},
		},
	}
	dialer := &testWebTerminalDialer{}
	terminal := &WebTerminal{cfg: config.Config{}, api: api, dialer: dialer}
	server := httptest.NewServer(terminal)
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):] + "?token=token-1"
	conn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_, _, err = conn.Read(context.Background())
	if err == nil {
		t.Fatal("expected policy violation close error")
	}
	closeStatus := websocket.CloseStatus(err)
	if closeStatus != websocket.StatusPolicyViolation {
		t.Fatalf("close status=%v want %v err=%v", closeStatus, websocket.StatusPolicyViolation, err)
	}
	if api.createCalls.Load() != 0 {
		t.Fatalf("CreateSession called %d times", api.createCalls.Load())
	}
	if dialer.dialCalls.Load() != 0 {
		t.Fatalf("dialSSH called %d times", dialer.dialCalls.Load())
	}
}

type testWebTerminalAPI struct {
	auth        targetAuthResult
	verifyErr   error
	createCalls atomic.Int32
}

func (a *testWebTerminalAPI) VerifyConnectionToken(context.Context, string, string) (targetAuthResult, error) {
	return a.auth, a.verifyErr
}

func (a *testWebTerminalAPI) CreateSession(context.Context, targetSessionInfo) (targetSessionInfo, error) {
	a.createCalls.Add(1)
	return targetSessionInfo{SessionID: 1}, nil
}

func (a *testWebTerminalAPI) GetSession(context.Context, int64) (targetSessionInfo, error) {
	return targetSessionInfo{}, nil
}

func (a *testWebTerminalAPI) FinishSession(context.Context, int64, string) error {
	return nil
}

func (a *testWebTerminalAPI) ListCommandFilterACLs(context.Context) ([]commandFilterRule, error) {
	return nil, nil
}

func (a *testWebTerminalAPI) GetSetting(context.Context, string) (string, error) {
	return "", nil
}

func (a *testWebTerminalAPI) GetHostKeys(context.Context) ([]string, error) {
	return nil, nil
}

func (a *testWebTerminalAPI) Audit(context.Context, int64, string, string, string, string) error {
	return nil
}

type testWebTerminalDialer struct {
	dialCalls atomic.Int32
}

func (d *testWebTerminalDialer) acquire() bool {
	return true
}

func (d *testWebTerminalDialer) release() {}

func (d *testWebTerminalDialer) dialSSH(context.Context, targetConfig, targetAccount) (*gossh.Client, error) {
	d.dialCalls.Add(1)
	return nil, nil
}

var _ apiClient = (*testWebTerminalAPI)(nil)
var _ webSSHDialer = (*testWebTerminalDialer)(nil)
