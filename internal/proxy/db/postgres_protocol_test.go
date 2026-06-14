package dbproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/tursom/turjmp/internal/config"
)

func TestPostgresStartupTokenAndProtocol(t *testing.T) {
	msg := &pgproto3.StartupMessage{Parameters: map[string]string{"user": "alice#token-1"}}
	if got := postgresStartupToken(msg); got != "token-1" {
		t.Fatalf("token=%q", got)
	}
	if got := postgresStartupToken(&pgproto3.StartupMessage{Parameters: map[string]string{"user": "token-2"}}); got != "token-2" {
		t.Fatalf("token=%q", got)
	}
	if postgresStartupToken(nil) != "" {
		t.Fatal("nil startup should not produce token")
	}
	if !isPostgresProtocol("postgres") || !isPostgresProtocol("postgresql") || isPostgresProtocol("mysql") {
		t.Fatal("unexpected postgres protocol classification")
	}
}

func TestPostgresRowsAffectedAndCancelBytes(t *testing.T) {
	tests := map[string]int64{
		"SELECT 3":     3,
		"UPDATE 12":    12,
		"INSERT 0 7":   7,
		"CREATE TABLE": -1,
		"":             -1,
	}
	for tag, want := range tests {
		if got := parsePostgresRowsAffected([]byte(tag)); got != want {
			t.Fatalf("tag %q got %d want %d", tag, got, want)
		}
	}

	var req pgproto3.CancelRequest
	raw := postgresCancelBytes(42, []byte{1, 2, 3, 4})
	if err := req.Decode(raw[4:]); err != nil {
		t.Fatal(err)
	}
	if req.ProcessID != 42 || string(req.SecretKey) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("bad cancel decode: %#v", req)
	}
}

func TestPostgresReceiveStartupRejectsSSLThenReadsStartup(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	proxy := newPostgresProxy(&testDBAPI{}, 1, time.Second, time.Second)
	gotCh := make(chan *pgproto3.StartupMessage, 1)
	go func() {
		backend := pgproto3.NewBackend(server, server)
		got, ok := proxy.receiveStartup(context.Background(), server, backend)
		if !ok {
			gotCh <- nil
			return
		}
		gotCh <- got
	}()

	ssl, err := (&pgproto3.SSLRequest{}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(ssl); err != nil {
		t.Fatal(err)
	}
	refusal := make([]byte, 1)
	if _, err := client.Read(refusal); err != nil {
		t.Fatal(err)
	}
	if refusal[0] != 'N' {
		t.Fatalf("ssl refusal=%q", refusal)
	}

	startup, err := (&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersion30,
		Parameters: map[string]string{
			"user":     "bob#token",
			"database": "app",
		},
	}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(startup); err != nil {
		t.Fatal(err)
	}
	got := <-gotCh
	if got == nil || got.Parameters["user"] != "bob#token" || got.Parameters["database"] != "app" {
		t.Fatalf("unexpected startup: %#v", got)
	}
}

func TestPostgresSendStartupOK(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	proxy := newPostgresProxy(&testDBAPI{}, 1, time.Second, time.Second)
	errCh := make(chan error, 1)
	go func() {
		backend := pgproto3.NewBackend(server, server)
		errCh <- proxy.sendStartupOK(backend, &postgresTarget{
			processID: 9,
			secretKey: []byte{1, 2, 3, 4},
			parameterStatuses: map[string]string{
				"server_version": "16",
			},
			txStatus: postgresReadyIdle,
		}, 77)
	}()

	frontend := pgproto3.NewFrontend(client, client)
	wantTypes := []string{"*pgproto3.AuthenticationOk", "*pgproto3.ParameterStatus", "*pgproto3.ParameterStatus", "*pgproto3.BackendKeyData", "*pgproto3.ReadyForQuery"}
	for _, want := range wantTypes {
		msg, err := frontend.Receive()
		if err != nil {
			t.Fatal(err)
		}
		if got := typeName(msg); got != want {
			t.Fatalf("got %s want %s", got, want)
		}
		if ps, ok := msg.(*pgproto3.ParameterStatus); ok && ps.Name == "bastion_session_id" && ps.Value != "77" {
			t.Fatalf("bad bastion session id: %#v", ps)
		}
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestPostgresAuditStateSimpleAndExtendedQueries(t *testing.T) {
	api := &testDBAPI{}
	state := newPostgresAuditState(context.Background(), api, 1, 99, "remote")

	state.observeFrontend(&pgproto3.Query{String: "select 1"})
	state.observeBackend(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})

	state.observeFrontend(&pgproto3.Parse{Name: "stmt", Query: "update t set a=1"})
	state.observeFrontend(&pgproto3.Bind{DestinationPortal: "portal", PreparedStatement: "stmt"})
	state.observeFrontend(&pgproto3.Execute{Portal: "portal"})
	state.observeBackend(&pgproto3.ErrorResponse{Code: "23505", Message: "duplicate"})

	if len(api.audits) != 2 {
		t.Fatalf("audit count=%d", len(api.audits))
	}
	first := decodeAuditDetail(t, api.audits[0])
	if first.Protocol != "postgres" || first.SQL != "select 1" || first.RowsAffected != 1 {
		t.Fatalf("unexpected first audit: %#v", first)
	}
	second := decodeAuditDetail(t, api.audits[1])
	if second.SQL != "update t set a=1" || !strings.Contains(second.Error, "23505") {
		t.Fatalf("unexpected second audit: %#v", second)
	}
}

func TestPostgresAuditStateFlushAndCopyPassthrough(t *testing.T) {
	api := &testDBAPI{}
	state := newPostgresAuditState(context.Background(), api, 7, 100, "remote")

	state.observeFrontend(&pgproto3.Query{String: "begin"})
	state.observeBackend(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	state.observeFrontend(&pgproto3.CopyData{Data: []byte("copy-payload")})
	state.observeBackend(&pgproto3.CopyInResponse{OverallFormat: 0})
	state.observeBackend(&pgproto3.CopyData{Data: []byte("server-copy")})

	if len(api.audits) != 1 {
		t.Fatalf("audit count=%d want 1", len(api.audits))
	}
	detail := decodeAuditDetail(t, api.audits[0])
	if detail.SQL != "begin" || detail.RowsAffected != 0 || detail.Error != "" {
		t.Fatalf("unexpected flushed audit: %#v", detail)
	}
}

func TestPostgresAuditStateCloseRemovesPreparedAndPortal(t *testing.T) {
	api := &testDBAPI{}
	state := newPostgresAuditState(context.Background(), api, 7, 100, "remote")

	state.observeFrontend(&pgproto3.Parse{Name: "stmt", Query: "select from prepared"})
	state.observeFrontend(&pgproto3.Bind{DestinationPortal: "portal", PreparedStatement: "stmt"})
	state.observeFrontend(&pgproto3.Close{ObjectType: 'P', Name: "portal"})
	state.observeFrontend(&pgproto3.Execute{Portal: "portal"})
	state.observeBackend(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})

	state.observeFrontend(&pgproto3.Bind{DestinationPortal: "portal2", PreparedStatement: "stmt"})
	state.observeFrontend(&pgproto3.Close{ObjectType: 'S', Name: "stmt"})
	state.observeFrontend(&pgproto3.Execute{Portal: "portal2"})
	state.observeBackend(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})

	if len(api.audits) != 1 {
		t.Fatalf("audit count=%d want 1", len(api.audits))
	}
	detail := decodeAuditDetail(t, api.audits[0])
	if detail.SQL != "select from prepared" {
		t.Fatalf("unexpected audit after close: %#v", detail)
	}
}

func TestPostgresCopyFrontendToTargetForwardsMessages(t *testing.T) {
	clientProxy, client := net.Pipe()
	defer clientProxy.Close()
	defer client.Close()
	targetProxy, target := net.Pipe()
	defer targetProxy.Close()
	defer target.Close()

	proxy := newPostgresProxy(&testDBAPI{}, 1, time.Second, 0)
	api := &testDBAPI{}
	audit := newPostgresAuditState(context.Background(), api, 1, 11, "remote")
	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.copyFrontendToTarget(
			context.Background(),
			clientProxy,
			pgproto3.NewBackend(clientProxy, clientProxy),
			&postgresTarget{conn: targetProxy, frontend: pgproto3.NewFrontend(targetProxy, targetProxy)},
			audit,
		)
	}()

	clientFrontend := pgproto3.NewFrontend(client, client)
	clientFrontend.Send(&pgproto3.Query{String: "select 42"})
	if err := clientFrontend.Flush(); err != nil {
		t.Fatal(err)
	}

	targetBackend := pgproto3.NewBackend(target, target)
	got, err := targetBackend.Receive()
	if err != nil {
		t.Fatal(err)
	}
	query, ok := got.(*pgproto3.Query)
	if !ok || query.String != "select 42" {
		t.Fatalf("unexpected forwarded message: %#v", got)
	}

	clientFrontend.Send(&pgproto3.Terminate{})
	if err := clientFrontend.Flush(); err != nil {
		t.Fatal(err)
	}
	got, err = targetBackend.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.(*pgproto3.Terminate); !ok {
		t.Fatalf("unexpected terminate message: %#v", got)
	}
	_ = target.Close()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if len(api.audits) != 0 {
		t.Fatalf("frontend-only forwarding should not complete audit, got %d", len(api.audits))
	}
}

func TestPostgresCopyTargetToFrontendForwardsAndAudits(t *testing.T) {
	clientProxy, client := net.Pipe()
	defer clientProxy.Close()
	defer client.Close()
	targetProxy, target := net.Pipe()
	defer targetProxy.Close()
	defer target.Close()

	proxy := newPostgresProxy(&testDBAPI{}, 1, time.Second, 0)
	api := &testDBAPI{}
	audit := newPostgresAuditState(context.Background(), api, 1, 12, "remote")
	audit.observeFrontend(&pgproto3.Query{String: "update t set a=1"})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.copyTargetToFrontend(
			ctx,
			pgproto3.NewBackend(clientProxy, clientProxy),
			&postgresTarget{conn: targetProxy, frontend: pgproto3.NewFrontend(targetProxy, targetProxy)},
			audit,
		)
	}()

	targetBackend := pgproto3.NewBackend(target, target)
	targetBackend.Send(&pgproto3.CommandComplete{CommandTag: []byte("UPDATE 5")})
	if err := targetBackend.Flush(); err != nil {
		t.Fatal(err)
	}

	clientFrontend := pgproto3.NewFrontend(client, client)
	got, err := clientFrontend.Receive()
	if err != nil {
		t.Fatal(err)
	}
	command, ok := got.(*pgproto3.CommandComplete)
	if !ok || string(command.CommandTag) != "UPDATE 5" {
		t.Fatalf("unexpected frontend message: %#v", got)
	}
	cancel()
	_ = target.Close()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	if len(api.audits) != 1 {
		t.Fatalf("audit count=%d want 1", len(api.audits))
	}
	detail := decodeAuditDetail(t, api.audits[0])
	if detail.SQL != "update t set a=1" || detail.RowsAffected != 5 {
		t.Fatalf("unexpected audit: %#v", detail)
	}
}

func TestPostgresSendErrorMessage(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- sendPostgresError(pgproto3.NewBackend(server, server), "28000", "bad token")
	}()

	msg, err := pgproto3.NewFrontend(client, client).Receive()
	if err != nil {
		t.Fatal(err)
	}
	pgErr, ok := msg.(*pgproto3.ErrorResponse)
	if !ok || pgErr.Code != "28000" || pgErr.Message != "bad token" {
		t.Fatalf("unexpected error response: %#v", msg)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestPostgresHandleConnRejectsMissingTokenAndProtocolMismatch(t *testing.T) {
	tests := []struct {
		name        string
		user        string
		api         *testDBAPI
		wantMessage string
		wantVerify  int
	}{
		{
			name:        "missing token",
			user:        "",
			api:         &testDBAPI{},
			wantMessage: "connection token required",
		},
		{
			name: "protocol mismatch",
			user: "alice#token-pg",
			api: &testDBAPI{
				verifyResult: authResult{Target: targetConfig{Protocol: "mysql"}},
			},
			wantMessage: "connection token protocol is not postgres",
			wantVerify:  1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()

			proxy := newPostgresProxy(tt.api, 1, time.Second, time.Second)
			done := make(chan struct{})
			go func() {
				defer close(done)
				proxy.handleConn(context.Background(), server)
			}()

			clientFrontend := pgproto3.NewFrontend(client, client)
			startup, err := (&pgproto3.StartupMessage{
				ProtocolVersion: pgproto3.ProtocolVersion30,
				Parameters: map[string]string{
					"user":     tt.user,
					"database": "app",
				},
			}).Encode(nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Write(startup); err != nil {
				t.Fatal(err)
			}
			msg, err := clientFrontend.Receive()
			if err != nil {
				t.Fatal(err)
			}
			pgErr, ok := msg.(*pgproto3.ErrorResponse)
			if !ok || pgErr.Message != tt.wantMessage {
				t.Fatalf("unexpected error response: %#v", msg)
			}
			<-done
			if got := tt.api.verifyCount(); got != tt.wantVerify {
				t.Fatalf("verify count=%d want %d", got, tt.wantVerify)
			}
			if got := tt.api.sessionCount(); got != 0 {
				t.Fatalf("session count=%d want 0", got)
			}
		})
	}
}

func TestPostgresCancelRegistryForwardsRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("listener unavailable in this environment: %v", err)
		}
		t.Fatal(err)
	}
	defer ln.Close()

	gotCh := make(chan pgproto3.CancelRequest, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		n, _ := conn.Read(buf)
		var req pgproto3.CancelRequest
		_ = req.Decode(buf[4:n])
		gotCh <- req
	}()

	registry := newPostgresCancelRegistry(200 * time.Millisecond)
	remove := registry.add(postgresCancelTarget{
		network:   "tcp",
		address:   ln.Addr().String(),
		processID: 123,
		secretKey: []byte{9, 8, 7, 6},
	})
	defer remove()

	err = registry.forward(context.Background(), &pgproto3.CancelRequest{ProcessID: 123, SecretKey: []byte{9, 8, 7, 6}})
	if err != nil {
		t.Fatal(err)
	}
	got := <-gotCh
	if got.ProcessID != 123 || string(got.SecretKey) != string([]byte{9, 8, 7, 6}) {
		t.Fatalf("bad forwarded cancel: %#v", got)
	}
}

func TestServerStartStopBothListeners(t *testing.T) {
	srv := NewServer(config.Config{
		Proxy: config.ProxyConfig{
			DB: config.DBProxyConfig{
				MySQLAddr:    "127.0.0.1:0",
				PostgresAddr: "127.0.0.1:0",
			},
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	deadline := time.After(2 * time.Second)
	for {
		srv.mu.Lock()
		listenerCount := len(srv.listeners)
		srv.mu.Unlock()
		if listenerCount == 2 {
			break
		}
		select {
		case err := <-errCh:
			if err != nil && strings.Contains(err.Error(), "operation not permitted") {
				t.Skipf("listener unavailable in this environment: %v", err)
			}
			t.Fatalf("server returned before listeners started: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for listeners")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	srv.Stop()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

type testDBAPI struct {
	mu           sync.Mutex
	audits       []string
	verifyResult authResult
	verifyErr    error
	verifyTokens []string
	expected     []string
	sessions     []sessionInfo
}

func (a *testDBAPI) VerifyConnectionToken(_ context.Context, token, _, expectedProtocol string) (authResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.verifyTokens = append(a.verifyTokens, token)
	a.expected = append(a.expected, expectedProtocol)
	return a.verifyResult, a.verifyErr
}

func (a *testDBAPI) PreflightConnectionToken(_ context.Context, token, _, expectedProtocol string) (authResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.verifyTokens = append(a.verifyTokens, token)
	a.expected = append(a.expected, expectedProtocol)
	return a.verifyResult, a.verifyErr
}

func (a *testDBAPI) CreateSession(_ context.Context, session sessionInfo) (sessionInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions = append(a.sessions, session)
	session.SessionID = int64(len(a.sessions))
	return session, nil
}

func (a *testDBAPI) FinishSession(context.Context, int64) error {
	return nil
}

func (a *testDBAPI) GetSession(context.Context, int64) (sessionInfo, error) {
	return sessionInfo{}, nil
}

func (a *testDBAPI) Audit(_ context.Context, _ int64, _, _, _ string, detail string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.audits = append(a.audits, detail)
	return nil
}

func (a *testDBAPI) GetSetting(context.Context, string) (string, error) {
	return "", nil
}

func (a *testDBAPI) verifyCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.verifyTokens)
}

func (a *testDBAPI) sessionCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.sessions)
}

func decodeAuditDetail(t *testing.T, raw string) sqlAuditDetail {
	t.Helper()
	var detail sqlAuditDetail
	if err := json.Unmarshal([]byte(raw), &detail); err != nil {
		t.Fatal(err)
	}
	return detail
}

func typeName(v any) string {
	return fmt.Sprintf("%T", v)
}
