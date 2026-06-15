package rdpproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tursom/turjmp/internal/config"
)

func TestAPIClientResolveNativeRDP(t *testing.T) {
	var gotPath string
	var gotSecret string
	var gotBody struct {
		RouteUsername string `json:"route_username"`
		Password      string `json:"password"`
		RemoteAddr    string `json:"remote_addr"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotSecret = r.Header.Get("X-Proxy-Auth")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{
			"user_id":11,
			"asset_id":22,
			"account_id":33,
			"target":{"address":"win.internal","port":3390,"protocol":"rdp"},
			"account":{"username":"administrator","secret":"target-password","secret_type":"password"}
		}}`))
	}))
	defer server.Close()

	client := NewAPIClient(config.Config{
		ProxyAuth: config.ProxyAuthConfig{Secret: "proxy-secret"},
		Proxy:     config.ProxyConfig{APIBaseURL: server.URL},
	})
	auth, err := client.ResolveNativeRDP(t.Context(), "alice#22#33", "front-password", "203.0.113.10:50000")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/proxy/rdp-native/resolve" || gotSecret != "proxy-secret" {
		t.Fatalf("path/secret=%q/%q", gotPath, gotSecret)
	}
	if gotBody.RouteUsername != "alice#22#33" || gotBody.Password != "front-password" || gotBody.RemoteAddr != "203.0.113.10:50000" {
		t.Fatalf("unexpected request body: %#v", gotBody)
	}
	if auth.UserID != 11 || auth.AssetID != 22 || auth.AccountID != 33 {
		t.Fatalf("unexpected identity: %#v", auth)
	}
	if auth.Target.Address != "win.internal" || auth.Target.Port != 3390 || auth.Target.Protocol != "rdp" {
		t.Fatalf("unexpected target: %#v", auth.Target)
	}
	if auth.Account.Username != "administrator" || auth.Account.Secret != "target-password" || auth.Account.SecretType != "password" {
		t.Fatalf("unexpected account: %#v", auth.Account)
	}
}

func TestAPIClientResolveNativeRDPDefaultsRDPPort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{
			"user_id":1,
			"asset_id":2,
			"account_id":3,
			"target":{"address":"win.internal","protocol":"rdp"},
			"account":{"username":"administrator","secret":"target-password","secret_type":"password"}
		}}`))
	}))
	defer server.Close()

	client := NewAPIClient(config.Config{Proxy: config.ProxyConfig{APIBaseURL: server.URL}})
	auth, err := client.ResolveNativeRDP(t.Context(), "alice#2#3", "front-password", "remote")
	if err != nil {
		t.Fatal(err)
	}
	if auth.Target.Port != 3389 {
		t.Fatalf("default target port=%d", auth.Target.Port)
	}
}
