package middleware

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestRequestCredentialCandidatesKeepCookieFallbacks(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://claudeapi.example/code/artifact/id", nil)
	req.Header.Set("Authorization", "Bearer unrelated-upstream-token")
	req.Header.Add("Cookie", AuthCookieName+"=stale")
	req.Header.Add("Cookie", AuthCookieName+"=current")

	got := requestCredentialCandidates(req)
	want := []string{"unrelated-upstream-token", "stale", "current"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("credential candidates = %#v, want %#v", got, want)
	}
}

func TestFirstValidCredentialSkipsInvalidAuthorizationAndOldCookie(t *testing.T) {
	candidates := []string{"unrelated-upstream-token", "stale", "current"}
	if got := firstValidCredential(candidates, func(value string) bool { return value == "current" }); got != "current" {
		t.Fatalf("first valid credential = %q, want current", got)
	}
}
func TestRequestCredentialCandidatesDeduplicatesAndCaps(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://claudeapi.example/code/artifact/id", nil)
	req.Header.Set("Authorization", "Bearer authorization")
	for _, value := range []string{"duplicate", "duplicate", "one", "two", "three", "four", "five", "six", "seven"} {
		req.Header.Add("Cookie", AuthCookieName+"="+value)
	}

	got := requestCredentialCandidates(req)
	want := []string{"authorization", "duplicate", "one", "two", "three", "four", "five", "six"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("credential candidates = %#v, want %#v", got, want)
	}
}
