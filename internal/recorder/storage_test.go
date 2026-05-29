package recorder

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLocalStoragePutGetURLDelete(t *testing.T) {
	storage := NewLocalStorage(t.TempDir())
	path, err := storage.Put(t.Context(), "session-1", strings.NewReader("cast-data"), 9)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, "session-1.cast") {
		t.Fatalf("unexpected path %q", path)
	}
	rc, err := storage.Get(t.Context(), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Close(); err != nil {
		t.Fatal(err)
	}
	if string(data) != "cast-data" {
		t.Fatalf("data=%q", data)
	}
	url, err := storage.URL(t.Context(), "session-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if url != path {
		t.Fatalf("url=%q path=%q", url, path)
	}
	if err := storage.Delete(t.Context(), "session-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected deleted file, err=%v", err)
	}
}

func TestLocalStorageDefaultsAndContextCancellation(t *testing.T) {
	storage := NewLocalStorage("")
	if storage.BasePath != "./recordings" {
		t.Fatalf("base path=%q", storage.BasePath)
	}
	storage.BasePath = t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path, err := storage.Put(ctx, "session-2", strings.NewReader("data"), 4)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("expected file still written before ctx check: %v", statErr)
	}
}
