package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTrustedProxyAPIRejectsMappedTrustAllBeforeSaving(t *testing.T) {
	r := httptest.NewRequest(http.MethodPut, "/api/audit/log-source/proxies",
		strings.NewReader(`{"proxies":"::ffff:0:0/96","forwardedHeadersSanitized":true}`))
	w := httptest.NewRecorder()
	auditTrustedProxiesHandler(nil)(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("mapped IPv4 trust-all must be rejected before writing: status=%d body=%s", w.Code, w.Body)
	}
}

func TestClipKeepsTextStorable(t *testing.T) {
	if got := clip("abc", 10); got != "abc" {
		t.Fatalf("%q", got)
	}
	cut := clip(strings.Repeat("я", 10), 7)
	if !utf8.ValidString(cut) || len(cut) > 7 || cut != strings.Repeat("я", 3) {
		t.Fatalf("a multi-byte character was split: %q", cut)
	}
	if strings.ContainsRune(clip("a\x00b", 10), 0) {
		t.Fatal("NUL cannot be stored in a text column")
	}
	if !utf8.ValidString(clip("a\xffb", 10)) {
		t.Fatal("invalid UTF-8 cannot be stored in a text column")
	}
}
