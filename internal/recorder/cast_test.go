package recorder

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"
)

func TestCastWriterWritesAsciicastV2Events(t *testing.T) {
	path := t.TempDir() + "/nested/session.cast"
	w, err := NewCastWriter(path, 120, 40)
	if err != nil {
		t.Fatal(err)
	}
	if w.Path() != path {
		t.Fatalf("path=%q", w.Path())
	}
	if err := w.WriteOutput([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteResize(100, 30); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var header map[string]any
	if err := dec.Decode(&header); err != nil {
		t.Fatal(err)
	}
	if header["version"].(float64) != 2 || header["width"].(float64) != 120 || header["height"].(float64) != 40 {
		t.Fatalf("unexpected header: %#v", header)
	}
	var output []any
	if err := dec.Decode(&output); err != nil {
		t.Fatal(err)
	}
	if output[1] != "o" || output[2] != "hello\n" {
		t.Fatalf("unexpected output event: %#v", output)
	}
	var resize []any
	if err := dec.Decode(&resize); err != nil {
		t.Fatal(err)
	}
	if resize[1] != "r" || resize[2] != "100x30" {
		t.Fatalf("unexpected resize event: %#v", resize)
	}
	if err := dec.Decode(&[]any{}); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestCastWriterDefaultsAndNilSafety(t *testing.T) {
	path := t.TempDir() + "/default.cast"
	w, err := NewCastWriter(path, 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteOutput(nil); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteResize(0, 24); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&header); err != nil {
		t.Fatal(err)
	}
	if header["width"].(float64) != 80 || header["height"].(float64) != 24 {
		t.Fatalf("unexpected defaults: %#v", header)
	}
	var nilWriter *CastWriter
	if nilWriter.Path() != "" {
		t.Fatal("nil Path should be empty")
	}
	if err := nilWriter.WriteOutput([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := nilWriter.WriteResize(1, 1); err != nil {
		t.Fatal(err)
	}
	if err := nilWriter.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRecordingWriterRecordsBeforeWritingDestination(t *testing.T) {
	path := t.TempDir() + "/record.cast"
	cast, err := NewCastWriter(path, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	var dst bytes.Buffer
	n, err := NewRecordingWriter(&dst, cast).Write([]byte("out"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || dst.String() != "out" {
		t.Fatalf("n=%d dst=%q", n, dst.String())
	}
	if err := cast.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"out"`)) {
		t.Fatalf("recording missing output: %s", raw)
	}
}
