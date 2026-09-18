package handler

import (
	"net/url"
	"strings"
	"testing"
)

func TestArtifactTicketDoesNotExposeCredential(t *testing.T) {
	token, err := issueArtifactTicket("admin-secret", "user@example.com")
	if err != nil || strings.Contains(token, "admin-secret") {
		t.Fatalf("invalid ticket: %q %v", token, err)
	}
	credential, email, path, ok := artifactAuth(authPrefix + token + "/artifact")
	if !ok || credential != "admin-secret" || email != "user@example.com" || path != "/artifact" {
		t.Fatalf("ticket lookup failed: %q %q %q %v", credential, email, path, ok)
	}
	if cookies := mergeProxyCookies("claude2api_auth=admin-secret; browser=1", "sessionKey=2"); strings.Contains(cookies, "admin-secret") {
		t.Fatalf("auth cookie leaked upstream: %s", cookies)
	}
}

func TestProxyTargetRoutesArtifactRequestsToArtifactHost(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		onMain bool
		want   string
	}{
		{name: "main frame", path: "/api/frame/types", onMain: true, want: artifactHost},
		{name: "uc frame", path: "/api/frame/frames", want: artifactHost},
		{name: "main artifact", path: "/code/artifact/id", onMain: true, want: artifactHost},
		{name: "uc artifact", path: "/code/artifact/id", want: artifactHost},
		{name: "legacy uc", path: "/legacy/path", want: ucHost},
		{name: "main assets", path: "/api/assets/app.js", onMain: true, want: assetsHost},
		{name: "main default", path: "/api/organizations/id", onMain: true, want: upstreamHost},
		{name: "frame lookalike", path: "/api/frameevil", onMain: true, want: upstreamHost},
		{name: "artifact lookalike", path: "/code/artifactx", onMain: true, want: upstreamHost},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, scheme := proxyTarget(tt.path, tt.onMain)
			if host != tt.want || scheme != "https" {
				t.Fatalf("proxyTarget(%q, %t) = (%q, %q), want (%q, https)", tt.path, tt.onMain, host, scheme, tt.want)
			}
		})
	}
}

func TestArtifactRedirectURLPreservesPathAndQuery(t *testing.T) {
	requestURL, err := url.Parse("/code/artifact/id?m=light&x=%2F")
	if err != nil {
		t.Fatal(err)
	}

	got := artifactRedirectURL("https://claudeapi.example/__auth/opaque-ticket", requestURL)
	want := "https://claudeapi.example/__auth/opaque-ticket/code/artifact/id?m=light&x=%2F"
	if got != want {
		t.Fatalf("artifact redirect = %q, want %q", got, want)
	}

	forceQueryURL := &url.URL{Path: "/code/artifact/id", ForceQuery: true}
	if got := artifactRedirectURL("https://claudeapi.example/__auth/opaque-ticket", forceQueryURL); got != "https://claudeapi.example/__auth/opaque-ticket/code/artifact/id?" {
		t.Fatalf("force-query artifact redirect = %q", got)
	}
}

func TestArtifactURLRewriting(t *testing.T) {
	mainOrigin := "https://claude.example"
	ucOrigin := "https://claudeapi.example/__auth/opaque-ticket"

	link := `<https://a.claude.ai/api/frame/types?org=x>; rel=preload, <https://cdn.example/app.js>; rel=preload`
	gotLink := rewriteResponseURL(link, mainOrigin, ucOrigin)
	if !strings.Contains(gotLink, `<https://claudeapi.example/__auth/opaque-ticket/api/frame/types?org=x>`) {
		t.Fatalf("artifact Link was not rewritten: %q", gotLink)
	}
	if !strings.Contains(gotLink, `https://cdn.example/app.js`) {
		t.Fatalf("unrelated Link target was changed: %q", gotLink)
	}

	body := string(rewriteBody([]byte(`src="https://a.claude.ai/code/artifact/id?m=light" api="//a.claude.ai/api/frame/types?org=x" targetOrigin="https://a.claude.ai"`), mainOrigin, ucOrigin))
	if !strings.Contains(body, `src="https://claudeapi.example/__auth/opaque-ticket/code/artifact/id?m=light"`) {
		t.Fatalf("artifact body URL was not rewritten: %q", body)
	}
	if !strings.Contains(body, `api="//claudeapi.example/__auth/opaque-ticket/api/frame/types?org=x"`) {
		t.Fatalf("frame body URL was not rewritten: %q", body)
	}
	if !strings.Contains(body, `targetOrigin="https://a.claude.ai"`) {
		t.Fatalf("bare artifact origin should not be rewritten: %q", body)
	}
}
