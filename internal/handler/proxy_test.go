package handler

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestArtifactTicketDoesNotExposeCredential(t *testing.T) {
	token, err := issueArtifactTicket("admin-secret", "user@example.com", "https://claude.example")
	if err != nil || strings.Contains(token, "admin-secret") {
		t.Fatalf("invalid ticket: %q %v", token, err)
	}
	ticket, path, ok := artifactTicketForPath(authPrefix + token + "/artifact")
	if !ok || ticket.credential != "admin-secret" || ticket.email != "user@example.com" || ticket.mainOrigin != "https://claude.example" || path != "/artifact" {
		t.Fatalf("ticket lookup failed: %#v %q %v", ticket, path, ok)
	}
	if cookies := mergeProxyCookies("claude2api_auth=admin-secret; pool_parent=https%3A%2F%2Fclaude.example; browser=1", "sessionKey=2"); strings.Contains(cookies, "admin-secret") || strings.Contains(cookies, "pool_parent") {
		t.Fatalf("mirror cookies leaked upstream: %s", cookies)
	}
}

func TestProxyTargetRoutesSandboxResourcesToArtifactHost(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		onMain   bool
		artifact bool
		want     string
	}{
		{name: "main frame", path: "/api/frame/types", onMain: true, want: upstreamHost},
		{name: "main artifact", path: "/code/artifact/id", onMain: true, want: artifactHost},
		{name: "sandbox root", path: "/", artifact: true, want: artifactHost},
		{name: "sandbox asset", path: "/_next/app.js", artifact: true, want: artifactHost},
		{name: "sandbox frame", path: "/api/frame/types", artifact: true, want: artifactHost},
		{name: "legacy sandbox", path: "/file", want: ucHost},
		{name: "main assets", path: "/api/assets/app.js", onMain: true, want: assetsHost},
		{name: "main default", path: "/api/organizations/id", onMain: true, want: upstreamHost},
		{name: "frame lookalike", path: "/api/frameevil", onMain: true, want: upstreamHost},
		{name: "artifact lookalike", path: "/code/artifactx", onMain: true, want: upstreamHost},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, scheme := proxyTarget(tt.path, tt.onMain, tt.artifact)
			if host != tt.want || scheme != "https" {
				t.Fatalf("proxyTarget(%q, %t, %t) = (%q, %q), want (%q, https)", tt.path, tt.onMain, tt.artifact, host, scheme, tt.want)
			}
		})
	}
}

func TestSandboxUpstreamPath(t *testing.T) {
	tests := []struct {
		path         string
		wantPath     string
		wantArtifact bool
	}{
		{path: "/", wantPath: "/", wantArtifact: true},
		{path: "/_next/app.js", wantPath: "/_next/app.js", wantArtifact: true},
		{path: "/_uc", wantPath: "/", wantArtifact: false},
		{path: "/_uc/file.js", wantPath: "/file.js", wantArtifact: false},
		{path: "/_ucx/file.js", wantPath: "/_ucx/file.js", wantArtifact: true},
	}
	for _, tt := range tests {
		gotPath, gotArtifact := sandboxUpstreamPath(tt.path)
		if gotPath != tt.wantPath || gotArtifact != tt.wantArtifact {
			t.Fatalf("sandboxUpstreamPath(%q) = (%q, %t), want (%q, %t)", tt.path, gotPath, gotArtifact, tt.wantPath, tt.wantArtifact)
		}
	}
}

func TestArtifactBootstrapRedirectPreservesPathAndQuery(t *testing.T) {
	requestURL, err := url.Parse("/__auth/opaque-ticket/code/artifact/id?m=light&x=%2F")
	if err != nil {
		t.Fatal(err)
	}
	got := sandboxRedirectURL("https://claudeapi.example", "/code/artifact/id", requestURL)
	want := "https://claudeapi.example/code/artifact/id?m=light&x=%2F"
	if got != want {
		t.Fatalf("sandbox redirect = %q, want %q", got, want)
	}

	forceQueryURL := &url.URL{Path: "/code/artifact/id", ForceQuery: true}
	if got := artifactRedirectURL("https://claudeapi.example/__auth/opaque-ticket", forceQueryURL); got != "https://claudeapi.example/__auth/opaque-ticket/code/artifact/id?" {
		t.Fatalf("ticket redirect = %q", got)
	}
}

func TestArtifactURLRewritingSeparatesResourceURLsAndTargetOrigin(t *testing.T) {
	mainOrigin := "https://claude.example"
	ticketBase := "https://claudeapi.example/__auth/opaque-ticket"
	legacyBase := ticketBase + ucPathPrefix

	body := string(rewriteBody([]byte(`root="https://a.claude.ai/" src="https://a.claude.ai/code/artifact/id?m=light" api="//a.claude.ai/api/frame/types?org=x" targetOrigin="https://a.claude.ai" legacy="https://www.claudeusercontent.com/file.js" lookalike="https://a.claude.aix/"`), mainOrigin, ticketBase, legacyBase))
	for _, want := range []string{
		`root="https://claudeapi.example/__auth/opaque-ticket/"`,
		`src="https://claudeapi.example/__auth/opaque-ticket/code/artifact/id?m=light"`,
		`api="//claudeapi.example/__auth/opaque-ticket/api/frame/types?org=x"`,
		`targetOrigin="https://claudeapi.example"`,
		`legacy="https://claudeapi.example/__auth/opaque-ticket/_uc/file.js"`,
		`lookalike="https://a.claude.aix/"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("rewritten body missing %q: %q", want, body)
		}
	}

	link := `<https://a.claude.ai/api/frame/types?org=x>; rel=preload, <https://www.claudeusercontent.com/file.js>; rel=preload, <https://cdn.example/app.js>; rel=preload`
	gotLink := rewriteResponseURL(link, mainOrigin, ticketBase, legacyBase)
	for _, want := range []string{
		`<https://claudeapi.example/__auth/opaque-ticket/api/frame/types?org=x>`,
		`<https://claudeapi.example/__auth/opaque-ticket/_uc/file.js>`,
		`https://cdn.example/app.js`,
	} {
		if !strings.Contains(gotLink, want) {
			t.Fatalf("rewritten Link missing %q: %q", want, gotLink)
		}
	}

	cleanBody := string(rewriteBody([]byte(`src="https://a.claude.ai/" targetOrigin="https://a.claude.ai"`), mainOrigin, "https://claudeapi.example", "https://claudeapi.example"+ucPathPrefix))
	if !strings.Contains(cleanBody, `src="https://claudeapi.example/"`) || !strings.Contains(cleanBody, `targetOrigin="https://claudeapi.example"`) {
		t.Fatalf("clean sandbox body was not rewritten: %q", cleanBody)
	}
}

func TestValidHTTPOrigin(t *testing.T) {
	if got := validHTTPOrigin("https://claude.example/path?x=1"); got != "https://claude.example" {
		t.Fatalf("validHTTPOrigin = %q", got)
	}
	if got := validHTTPOrigin("javascript:alert(1)"); got != "" {

		t.Fatalf("unsafe origin accepted: %q", got)
	}
}
func TestArtifactTemplateLiteralURLRewriting(t *testing.T) {
	mainOrigin := "https://claude.example"
	ticketBase := "https://claudeapi.example/__auth/opaque-ticket"
	legacyBase := ticketBase + ucPathPrefix
	body := string(rewriteBody([]byte("src=`https://a.claude.ai`"), mainOrigin, ticketBase, legacyBase))
	if !strings.Contains(body, "src=`https://claudeapi.example`") {
		t.Fatalf("template literal URL was not rewritten: %q", body)
	}
}

func TestProxyModifyResponsePreservesSecureForHTTPSClient(t *testing.T) {
	cookie := "session=abc; Domain=a.claude.ai; Path=/; SameSite=None; Secure"
	req, err := http.NewRequest(http.MethodGet, "https://mirror.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, &proxyCtx{downstreamHTTPS: true, artifactTicketed: true}))
	resp := &http.Response{
		Header:  http.Header{"Set-Cookie": []string{cookie}},
		Body:    http.NoBody,
		Request: req,
	}
	if err := proxyModifyResponse(resp); err != nil {
		t.Fatal(err)
	}
	got := resp.Header.Get("Set-Cookie")
	if strings.Contains(got, "Domain=") || !strings.Contains(got, "Secure") {
		t.Fatalf("HTTPS response cookie was downgraded: %q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("ticketed response cache control = %q", got)
	}
}

func TestRewriteProxySetCookieKeepsSecureOnHTTPS(t *testing.T) {
	cookie := "session=abc; Domain=a.claude.ai; Path=/; SameSite=None; Secure"
	if got := rewriteProxySetCookie(cookie, true); strings.Contains(got, "Domain=") || !strings.Contains(got, "Secure") {
		t.Fatalf("HTTPS cookie rewrite = %q", got)
	}
	if got := rewriteProxySetCookie(cookie, false); strings.Contains(got, "Domain=") || strings.Contains(got, "Secure") {
		t.Fatalf("HTTP cookie rewrite = %q", got)
	}
}
func TestSandboxParentOriginUsesTrustedCookie(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://claudeapi.example/?parentOrigin=https://attacker.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	if got := sandboxParentOrigin(map[string]string{sandboxParentCookieName: "https://claude.example"}, req); got != "https://claude.example" {
		t.Fatalf("trusted parent origin = %q", got)
	}
	if got := sandboxParentOrigin(nil, req); got != "https://claudeapi.example" {
		t.Fatalf("query parent origin was trusted: %q", got)
	}
}
