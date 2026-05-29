package rdpproxy

import (
	"net"
	"testing"

	"github.com/tursom/turjmp/internal/config"
)

func TestRDPConfigDefaults(t *testing.T) {
	var cfg config.RDPProxyConfig
	if got := cfg.ListenAddr(); got != ":33891" {
		t.Fatalf("listen addr=%q", got)
	}
	if got := cfg.GuacdListenAddr(); got != "127.0.0.1:4822" {
		t.Fatalf("guacd addr=%q", got)
	}
	if got := cfg.RecordingDir(); got != "./recordings/rdp-tmp" {
		t.Fatalf("recording dir=%q", got)
	}
	if got := cfg.ConnectionLimit(); got != 20 {
		t.Fatalf("limit=%d", got)
	}
	if got := cfg.IdleTimeout().Seconds(); got != 3600 {
		t.Fatalf("idle timeout=%v", got)
	}
	if got := cfg.ConnectTimeout().Seconds(); got != 15 {
		t.Fatalf("connect timeout=%v", got)
	}
}

func TestRDPHelpers(t *testing.T) {
	if !isRDPProtocol("RDP") || isRDPProtocol("ssh") {
		t.Fatal("unexpected RDP protocol detection")
	}
	if got := rdpTargetPort(targetConfig{Protocol: "rdp"}); got != 3389 {
		t.Fatalf("default port=%d", got)
	}
	if got := rdpTargetPort(targetConfig{Protocol: "rdp", Port: 3390}); got != 3390 {
		t.Fatalf("explicit port=%d", got)
	}
	if got := parseSettingString(`"./recordings"`, "fallback"); got != "./recordings" {
		t.Fatalf("setting string=%q", got)
	}
	if got := parsePositiveInt(`"144"`, 96); got != 144 {
		t.Fatalf("positive int=%d", got)
	}
	if got := parsePositiveInt("bad", 96); got != 96 {
		t.Fatalf("fallback int=%d", got)
	}
	if got := safeRemoteAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}); got != "127.0.0.1:1234" {
		t.Fatalf("remote addr=%q", got)
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(1)
	if !l.acquire() {
		t.Fatal("first acquire should pass")
	}
	if l.acquire() {
		t.Fatal("second acquire should fail")
	}
	l.release()
	l.release()
	if !l.acquire() {
		t.Fatal("acquire after release should pass")
	}
}
