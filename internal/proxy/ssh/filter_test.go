package sshproxy

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestCommandFilterRejectsDeniedLine(t *testing.T) {
	filter := &commandFilter{rules: []compiledRule{mustRule(t, "danger", "rm -rf", "deny")}}
	var notice bytes.Buffer
	reader := newFilteringReader(strings.NewReader("echo ok\nrm -rf /\nwhoami\n"), &notice, filter)
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); got != "echo ok\nwhoami\n" {
		t.Fatalf("filtered output = %q", got)
	}
	if !strings.Contains(notice.String(), "command rejected by policy: danger") {
		t.Fatalf("missing rejection notice: %q", notice.String())
	}
}

func TestCommandFilterAllowsReview(t *testing.T) {
	filter := &commandFilter{rules: []compiledRule{mustRule(t, "review", "sudo", "review")}}
	reader := newFilteringReader(strings.NewReader("sudo id\n"), io.Discard, filter)
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); got != "sudo id\n" {
		t.Fatalf("filtered output = %q", got)
	}
}

func mustRule(t *testing.T, name, pattern, action string) compiledRule {
	t.Helper()
	filter := &commandFilter{}
	rules := []commandFilterRule{{Name: name, Pattern: pattern, Action: action}}
	api := staticRuleAPI{rules: rules}
	loaded, err := loadCommandFilter(t.Context(), api)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(loaded.rules))
	}
	_ = filter
	return loaded.rules[0]
}

type staticRuleAPI struct {
	rules []commandFilterRule
}

func (s staticRuleAPI) VerifyConnectionToken(context.Context, string, string) (targetAuthResult, error) {
	return targetAuthResult{}, nil
}
func (s staticRuleAPI) CreateSession(context.Context, targetSessionInfo) (targetSessionInfo, error) {
	return targetSessionInfo{}, nil
}
func (s staticRuleAPI) FinishSession(context.Context, int64, string) error { return nil }
func (s staticRuleAPI) ListCommandFilterACLs(context.Context) ([]commandFilterRule, error) {
	return s.rules, nil
}
func (s staticRuleAPI) GetSetting(context.Context, string) (string, error) { return "", nil }
func (s staticRuleAPI) GetHostKeys(context.Context) ([]string, error)      { return nil, nil }
func (s staticRuleAPI) Audit(context.Context, int64, string, string, string, string) error {
	return nil
}
