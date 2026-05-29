package service

import (
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/tursom/turjmp/internal/config"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

func TestGenerateHostKey(t *testing.T) {
	for _, algorithm := range []string{"ssh-ed25519", "ssh-rsa"} {
		t.Run(algorithm, func(t *testing.T) {
			key, err := generateHostKey(algorithm)
			if err != nil {
				t.Fatal(err)
			}
			if key.Algorithm != algorithm || key.Fingerprint == "" || key.PrivateKey == "" || key.PublicKey == "" {
				t.Fatalf("incomplete key: %#v", key)
			}
			signer, err := gossh.ParsePrivateKey([]byte(key.PrivateKey))
			if err != nil {
				t.Fatal(err)
			}
			if got := gossh.FingerprintSHA256(signer.PublicKey()); got != key.Fingerprint {
				t.Fatalf("fingerprint got %q want %q", got, key.Fingerprint)
			}
		})
	}
}

func TestGenerateHostKeyRejectsUnsupportedAlgorithm(t *testing.T) {
	if _, err := generateHostKey("ecdsa"); err == nil {
		t.Fatal("expected unsupported algorithm error")
	}
}

func TestHostKeyServiceEnsureDefaultsIsIdempotent(t *testing.T) {
	store, closeFn := newHostKeyTestStore(t)
	defer closeFn()
	svc := NewHostKeyService(store)

	first, err := svc.EnsureDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 {
		t.Fatalf("expected 2 host keys, got %d", len(first))
	}
	second, err := svc.EnsureDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 2 {
		t.Fatalf("expected 2 host keys on second call, got %d", len(second))
	}
	if first[0].Fingerprint != second[0].Fingerprint || first[1].Fingerprint != second[1].Fingerprint {
		t.Fatalf("expected idempotent fingerprints first=%#v second=%#v", first, second)
	}
	signers, err := svc.Signers()
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 2 {
		t.Fatalf("expected 2 signers, got %d", len(signers))
	}
}

func TestHostKeyServiceSignersReportsBadPrivateKey(t *testing.T) {
	store, closeFn := newHostKeyTestStore(t)
	defer closeFn()
	key := mustGenerateHostKey(t, "ssh-ed25519")
	key.PrivateKey = "not-a-private-key"
	if err := store.CreateHostKey(&key); err != nil {
		t.Fatal(err)
	}
	_, err := NewHostKeyService(store).Signers()
	if err == nil {
		t.Fatalf("expected parse private key error, got %v", err)
	}
}

func newHostKeyTestStore(t *testing.T) (*repository.Store, func()) {
	t.Helper()
	db, err := repository.NewDB(config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    "file:" + t.TempDir() + "/hostkeys.db?_pragma=foreign_keys(ON)",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE host_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		algorithm TEXT NOT NULL,
		fingerprint TEXT NOT NULL UNIQUE,
		private_key TEXT NOT NULL,
		public_key TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	return repository.NewStore(db), func() { _ = db.Close() }
}

func mustGenerateHostKey(t *testing.T, algorithm string) domain.HostKey {
	t.Helper()
	key, err := generateHostKey(algorithm)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
