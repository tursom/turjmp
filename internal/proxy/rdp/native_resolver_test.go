package rdpproxy

import (
	"context"
	"testing"
)

func TestNativeResolverDelegatesAndValidates(t *testing.T) {
	api := &fakeAPI{
		auth: authResult{
			UserID:    11,
			AssetID:   22,
			AccountID: 33,
			Target:    targetConfig{Address: "win.internal", Port: 3389, Protocol: "rdp"},
			Account:   targetAccount{Username: "administrator", Secret: "target-password", SecretType: "password"},
		},
	}
	resolved, err := NewNativeResolver(api).Resolve(context.Background(), "alice#22#33", "front-password", "remote")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.UserID != 11 || resolved.Target.Address != "win.internal" || resolved.Account.Secret != "target-password" {
		t.Fatalf("unexpected resolved auth: %#v", resolved)
	}

	api.auth.Target.Protocol = "ssh"
	if _, err := NewNativeResolver(api).Resolve(context.Background(), "alice#22#33", "front-password", "remote"); err == nil {
		t.Fatal("expected validation error for non-rdp target")
	}
}
