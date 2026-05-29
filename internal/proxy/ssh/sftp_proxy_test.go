package sshproxy

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/pkg/sftp"
)

func TestParseSFTPPolicyAndPathChecks(t *testing.T) {
	policy := parseSFTPPolicy(`2048`, `"/etc/shadow,/secret"`)
	if policy.MaxFileSize != 2048 {
		t.Fatalf("max file size=%d", policy.MaxFileSize)
	}
	h := &remoteSFTPHandlers{policy: policy}
	if err := h.checkPath("/tmp/ok"); err != nil {
		t.Fatalf("allowed path rejected: %v", err)
	}
	for _, path := range []string{"/etc/shadow", "/secret/file", "secret/nested"} {
		t.Run(path, func(t *testing.T) {
			if err := h.checkPath(path); err == nil || !strings.Contains(err.Error(), "path denied") {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestParseSFTPPolicyDefaults(t *testing.T) {
	policy := parseSFTPPolicy("", "")
	if policy.MaxFileSize != 1<<30 {
		t.Fatalf("default max file size=%d", policy.MaxFileSize)
	}
	h := &remoteSFTPHandlers{policy: policy}
	if err := h.checkPath("/etc/passwd"); err == nil {
		t.Fatal("expected default denied path")
	}
}

func TestOpenFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags sftp.FileOpenFlags
		want  int
	}{
		{name: "read", flags: sftp.FileOpenFlags{Read: true}, want: os.O_RDONLY},
		{name: "write create trunc", flags: sftp.FileOpenFlags{Write: true, Creat: true, Trunc: true}, want: os.O_WRONLY | os.O_CREATE | os.O_TRUNC},
		{name: "read write append excl", flags: sftp.FileOpenFlags{Read: true, Write: true, Append: true, Excl: true}, want: os.O_RDWR | os.O_APPEND | os.O_EXCL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := openFlags(tt.flags); got != tt.want {
				t.Fatalf("got %d want %d", got, tt.want)
			}
		})
	}
}

func TestFileInfoListListAtAndRename(t *testing.T) {
	file := t.TempDir() + "/one.txt"
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	list := fileInfoList{renameFileInfo{name: "renamed.txt", FileInfo: info}}
	dst := make([]os.FileInfo, 2)
	n, err := list.ListAt(dst, 0)
	if n != 1 || err != io.EOF {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if dst[0].Name() != "renamed.txt" {
		t.Fatalf("name=%q", dst[0].Name())
	}
	n, err = list.ListAt(dst, 1)
	if n != 0 || err != io.EOF {
		t.Fatalf("offset eof n=%d err=%v", n, err)
	}
}
