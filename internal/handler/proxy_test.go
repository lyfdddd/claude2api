package handler

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
	if cookies := mergeProxyCookies("claude2api_auth=admin-secret; pool_parent=https%3A%2F%2Fclaude.example; pool_sandbox_binding=opaque; browser=1", "sessionKey=2"); strings.Contains(cookies, "admin-secret") || strings.Contains(cookies, "pool_parent") || strings.Contains(cookies, "pool_sandbox_binding") {
		t.Fatalf("mirror cookies leaked upstream: %s", cookies)
	}
}

func TestProxyTargetRoutesArtifactViewerAndAPIsToMainHost(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		onMain bool
		want   string
	}{
		{name: "main frame API", path: "/api/frame/types", onMain: true, want: upstreamHost},
		{name: "main artifact viewer", path: "/code/artifact/id", onMain: true, want: upstreamHost},
		{name: "sandbox legacy fallback", path: "/file", want: ucHost},
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

func TestSandboxRouteForPath(t *testing.T) {
	tests := []struct {
		name       string
		rawPath    string
		wantPath   string
		wantHost   string
		wantLegacy bool
		wantLabel  string
		wantOK     bool
	}{
		{name: "legacy root", rawPath: "/_uc", wantPath: "/", wantHost: ucHost, wantLegacy: true, wantOK: true},
		{name: "legacy asset", rawPath: "/_uc/_next/app.js", wantPath: "/_next/app.js", wantHost: ucHost, wantLegacy: true, wantOK: true},
		{name: "valid UUID frame", rawPath: "/_frame/30539b3e-4287-4947-9dfb-d32ce553d9a0/_f/v/", wantPath: "/_f/v/", wantHost: "30539b3e-4287-4947-9dfb-d32ce553d9a0.frame.claudeusercontent.com", wantLabel: "30539b3e-4287-4947-9dfb-d32ce553d9a0", wantOK: true},
		{name: "single-label frame", rawPath: "/_frame/a", wantPath: "/", wantHost: "a.frame.claudeusercontent.com", wantLabel: "a", wantOK: true},
		{name: "hyphen label", rawPath: "/_frame/abc-1/assets/app.js", wantPath: "/assets/app.js", wantHost: "abc-1.frame.claudeusercontent.com", wantLabel: "abc-1", wantOK: true},
		{name: "sandbox root rejected", rawPath: "/", wantOK: false},
		{name: "frame dot rejected", rawPath: "/_frame/a.bad/file", wantOK: false},
		{name: "frame port rejected", rawPath: "/_frame/a:443/file", wantOK: false},
		{name: "frame at rejected", rawPath: "/_frame/a@host/file", wantOK: false},
		{name: "frame underscore rejected", rawPath: "/_frame/a_b/file", wantOK: false},
		{name: "leading hyphen rejected", rawPath: "/_frame/-bad/file", wantOK: false},
		{name: "trailing hyphen rejected", rawPath: "/_frame/bad-/file", wantOK: false},
		{name: "encoded slash rejected", rawPath: "/_frame/a%2Fbad/file", wantOK: false},
		{name: "lookalike legacy rejected", rawPath: "/_ucx/file", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, ok := sandboxRouteForPath(tt.rawPath)
			if ok != tt.wantOK {
				t.Fatalf("sandboxRouteForPath(%q) ok = %t, want %t", tt.rawPath, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if route.upstreamPath != tt.wantPath || route.targetHost != tt.wantHost || route.legacy != tt.wantLegacy || route.frameLabel != tt.wantLabel {
				t.Fatalf("sandboxRouteForPath(%q) = %#v, want path=%q host=%q legacy=%t label=%q", tt.rawPath, route, tt.wantPath, tt.wantHost, tt.wantLegacy, tt.wantLabel)
			}
		})
	}
}

func TestFrameMethodsAreReadOnly(t *testing.T) {
	for _, tt := range []struct {
		method string
		want   bool
	}{
		{method: http.MethodGet, want: true},
		{method: http.MethodHead, want: true},
		{method: http.MethodPost, want: false},
		{method: http.MethodPut, want: false},
		{method: http.MethodOptions, want: false},
	} {
		if got := allowsFrameMethod(tt.method); got != tt.want {
			t.Fatalf("allowsFrameMethod(%q) = %t, want %t", tt.method, got, tt.want)
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

func TestArtifactURLRewritingKeepsLegacyViewerOnMainOrigin(t *testing.T) {
	mainOrigin := "https://claude.example"
	ticketBase := "https://claudeapi.example/__auth/opaque-ticket"
	legacyBase := ticketBase + ucPathPrefix

	body := string(rewriteBody([]byte(`root="https://a.claude.ai/" src="https://a.claude.ai/code/artifact/id?m=light" api="//a.claude.ai/api/frame/types?org=x" legacy="https://www.claudeusercontent.com/file.js" lookalike="https://a.claude.aix/"`), mainOrigin, ticketBase, legacyBase))
	for _, want := range []string{
		`root="https://claude.example/"`,
		`src="https://claude.example/code/artifact/id?m=light"`,
		`api="//claude.example/api/frame/types?org=x"`,
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
		`<https://claude.example/api/frame/types?org=x>`,
		`<https://claudeapi.example/__auth/opaque-ticket/_uc/file.js>`,
		`https://cdn.example/app.js`,
	} {
		if !strings.Contains(gotLink, want) {
			t.Fatalf("rewritten Link missing %q: %q", want, gotLink)
		}
	}
}
func TestDynamicFrameURLRewritingPreservesToken(t *testing.T) {
	mainOrigin := "https://claude.example"
	ticketBase := "https://claudeapi.example/__auth/opaque-ticket"
	legacyBase := ticketBase + ucPathPrefix
	input := `frame="https://30539b3e-4287-4947-9dfb-d32ce553d9a0.frame.claudeusercontent.com/_f/v/?__frame_t=token%2Bvalue&x=1" protocol="//a.frame.claudeusercontent.com/_f/v/?__frame_t=t" invalid="https://bad.host.frame.claudeusercontent.com/_f/v/?__frame_t=no"`
	got := string(rewriteBody([]byte(input), mainOrigin, ticketBase, legacyBase))
	for _, want := range []string{
		`https://claudeapi.example/__auth/opaque-ticket/_frame/30539b3e-4287-4947-9dfb-d32ce553d9a0/_f/v/?__frame_t=token%2Bvalue&x=1`,
		`//claudeapi.example/__auth/opaque-ticket/_frame/a/_f/v/?__frame_t=t`,
		`https://bad.host.frame.claudeusercontent.com/_f/v/?__frame_t=no`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rewritten dynamic frame URL missing %q: %q", want, got)
		}
	}

	location := rewriteResponseURL(`https://a.frame.claudeusercontent.com/_f/v/?__frame_t=kept`, mainOrigin, ticketBase, legacyBase)
	if location != `https://claudeapi.example/__auth/opaque-ticket/_frame/a/_f/v/?__frame_t=kept` {
		t.Fatalf("rewritten dynamic frame Location = %q", location)
	}
}

func TestDynamicFrameURLRewritingHandlesSerializedOriginsAndPorts(t *testing.T) {
	ticketBase := "https://claudeapi.example/__auth/opaque-ticket"
	input := `normal=https://a.frame.claudeusercontent.com/_f/v/?__frame_t=normal escaped=https:\/\/a.frame.claudeusercontent.com\/_f\/v\/?__frame_t=escaped unicode=https:\u002F\u002Fa.frame.claudeusercontent.com\u002F_f\u002Fv\u002F?__frame_t=unicode hybrid=https:\/\/a.frame.claudeusercontent.com/_f/v/?__frame_t=hybrid port=https://a.frame.claudeusercontent.com:443/_f/v/?__frame_t=port`
	got := rewriteFrameURLs(input, ticketBase)
	for _, want := range []string{
		`https://claudeapi.example/__auth/opaque-ticket/_frame/a/_f/v/?__frame_t=normal`,
		`https:\/\/claudeapi.example\/__auth\/opaque-ticket\/_frame\/a\/_f\/v\/?__frame_t=escaped`,
		`https:\u002F\u002Fclaudeapi.example\u002F__auth\u002Fopaque-ticket\u002F_frame\u002Fa\u002F_f\u002Fv\u002F?__frame_t=unicode`,
		`https:\/\/claudeapi.example\/__auth\/opaque-ticket\/_frame\/a/_f/v/?__frame_t=hybrid`,
		`https://a.frame.claudeusercontent.com:443/_f/v/?__frame_t=port`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rewritten serialized frame URL missing %q: %q", want, got)
		}
	}
}

func TestPostMessageTargetOriginsFollowMessageDirection(t *testing.T) {
	mainOrigin := "https://claude.example"
	ticketBase := "https://claudeapi.example/__auth/opaque-ticket"
	legacyBase := ticketBase + ucPathPrefix

	wrapper := `parent={targetOrigin:"https://claude.ai"} legacy={targetOrigin:"https://a.claude.ai"} child={targetOrigin:"https://a.frame.claudeusercontent.com"}`
	wrapper = string(rewriteBody([]byte(rewriteMainPostMessageTargetOrigins(wrapper, ticketBase)), mainOrigin, ticketBase, legacyBase))
	if strings.Count(wrapper, `targetOrigin:"https://claudeapi.example"`) != 2 {
		t.Fatalf("main wrapper did not target sandbox child origin: %q", wrapper)
	}
	if !strings.Contains(wrapper, `targetOrigin:"https://claude.example"`) {
		t.Fatalf("main wrapper did not retain main parent origin: %q", wrapper)
	}
	if strings.Contains(wrapper, `targetOrigin:"https://claudeapi.example/__auth/`) {
		t.Fatalf("postMessage target origin incorrectly includes a path: %q", wrapper)
	}

	frame := `parent={targetOrigin:"https://claude.ai"} legacy={targetOrigin:"https://a.claude.ai"}`
	frame = string(rewriteBody([]byte(rewriteFramePostMessageTargetOrigins(frame, mainOrigin)), mainOrigin, "https://claudeapi.example", "https://claudeapi.example/_uc"))
	if strings.Count(frame, `targetOrigin:"https://claude.example"`) != 2 {
		t.Fatalf("frame did not target the mirrored parent origin: %q", frame)
	}
	if strings.Contains(frame, "claudeapi.example") {
		t.Fatalf("frame postMessage target incorrectly points to sandbox: %q", frame)
	}
}

func TestFrameRootURLRewritingOnlyChangesURLContexts(t *testing.T) {
	label := "a"
	html := `<base href="/"><script src=/assets/app.js></script><img src=//cdn.example/img.png><img src="/_frame/a/ready.js"><a href="\/assets/escaped.js"><a href="\u002Fassets/unicode.js"><a href="\u002F_frame\u002Fa\u002Fready.js">`
	htmlGot := rewriteFrameRootURLs(html, label, "text/html")
	for _, want := range []string{
		`<base href="/_frame/a/">`,
		`src=/_frame/a/assets/app.js`,
		`src=//cdn.example/img.png`,
		`src="/_frame/a/ready.js"`,
		`href="\/_frame\/a\/assets/escaped.js"`,
		`href="\u002F_frame\u002Fa\u002Fassets\u002Funicode.js"`,
		`href="\u002F_frame\u002Fa\u002Fready.js"`,
	} {
		if !strings.Contains(htmlGot, want) {
			t.Fatalf("rewritten HTML missing %q: %q", want, htmlGot)
		}
	}
	if again := rewriteFrameRootURLs(htmlGot, label, "text/html"); again != htmlGot {
		t.Fatalf("HTML root rewrite was not idempotent: %q", again)
	}

	js := `const pattern = /foo/; const quotient = a / b; const asset = "/assets/app.js";`
	jsGot := rewriteFrameRootURLs(js, label, "application/javascript")
	if !strings.Contains(jsGot, `const pattern = /foo/; const quotient = a / b;`) || !strings.Contains(jsGot, `const asset = "/_frame/a/assets/app.js";`) {
		t.Fatalf("JavaScript URL rewrite changed syntax or missed asset: %q", jsGot)
	}

	css := `a{background:url(/assets/site.css)} b{background:url(//cdn.example/site.css)} c{background:url(/_frame/a/ready.css)}`
	cssGot := rewriteFrameRootURLs(css, label, "text/css")
	for _, want := range []string{`url(/_frame/a/assets/site.css)`, `url(//cdn.example/site.css)`, `url(/_frame/a/ready.css)`} {
		if !strings.Contains(cssGot, want) {
			t.Fatalf("rewritten CSS missing %q: %q", want, cssGot)
		}
	}

	for input, want := range map[string]string{
		`/assets/redirect.js`:           `/_frame/a/assets/redirect.js`,
		`</assets/preload.js>; rel=preload`: `</_frame/a/assets/preload.js>; rel=preload`,
		`//cdn.example/file.js`:         `//cdn.example/file.js`,
		`/_frame/a/already.js`:          `/_frame/a/already.js`,
	} {
		if got := rewriteFrameHeaderRootURL(input, label); got != want {
			t.Fatalf("frame header rewrite %q = %q, want %q", input, got, want)
		}
	}
}

func TestSandboxBindingIsOpaqueAndCookieProtected(t *testing.T) {
	binding, err := issueSandboxBinding("user@example.com")
	if err != nil || binding == "" || binding == "user@example.com" {
		t.Fatalf("invalid sandbox binding: %q %v", binding, err)
	}
	if got := sandboxBindingEmail(binding); got != "user@example.com" {
		t.Fatalf("sandbox binding resolved to %q", got)
	}
	if got := sandboxBindingEmail("not-a-binding"); got != "" {
		t.Fatalf("unknown sandbox binding resolved to %q", got)
	}

	recorder := httptest.NewRecorder()
	setSandboxTicketCookies(recorder, artifactTicket{mainOrigin: "https://claude.example"}, binding, true)
	cookies := recorder.Result().Cookies()
	foundBinding, foundParent := false, false
	for _, cookie := range cookies {
		switch cookie.Name {
		case sandboxBindingCookieName:
			foundBinding = cookie.Value == binding && cookie.HttpOnly && cookie.Secure
		case sandboxParentCookieName:
			foundParent = cookie.HttpOnly && cookie.Secure
		case "pool_acct":
			t.Fatalf("sandbox response exposed writable account cookie")
		}
	}
	if !foundBinding || !foundParent {
		t.Fatalf("sandbox cookies were incomplete or not protected: %#v", cookies)
	}
}
func TestProxyDirectorDoesNotSendCookieToDynamicFrame(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://claudeapi.example/_frame/a/_f/v/?__frame_t=token", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", "browser=1")
	pc := &proxyCtx{
		email: "user@example.com", browserCookies: req.Header.Get("Cookie"),
		targetHost: "a.frame.claudeusercontent.com", frameLabel: "a",
	}
	req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, pc))
	proxyDirector(req)
	if got := req.Header.Get("Cookie"); got != "" {
		t.Fatalf("dynamic frame request leaked cookie upstream: %q", got)
	}
	if req.URL.Host != "a.frame.claudeusercontent.com" || req.Host != "a.frame.claudeusercontent.com" {
		t.Fatalf("dynamic frame request targeted %q / %q", req.URL.Host, req.Host)
	}
}
func TestFrameResponseIsolatedAndNamespaced(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://claudeapi.example/_frame/a/_f/v/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, &proxyCtx{
		mainOrig: "https://claude.example", artifactOrig: "https://claudeapi.example",
		ucOrig: "https://claudeapi.example/_uc", frameLabel: "a",
	}))
	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"text/html; charset=utf-8"},
			"Set-Cookie":   []string{"upstream=secret; Domain=a.frame.claudeusercontent.com; Path=/"},
			"Location":     []string{"/assets/redirect.js"},
			"Link":         []string{`</assets/preload.js>; rel=preload`},
		},
		Body: io.NopCloser(strings.NewReader(`<base href="/"><script src="/assets/app.js"></script>`)),
		Request: req,
	}
	if err := proxyModifyResponse(resp); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); !strings.Contains(got, `<base href="/_frame/a/">`) || !strings.Contains(got, `src="/_frame/a/assets/app.js"`) {
		t.Fatalf("frame body was not namespaced: %q", got)
	}
	if got := resp.Header.Get("Location"); got != "/_frame/a/assets/redirect.js" {
		t.Fatalf("frame Location = %q", got)
	}
	if got := resp.Header.Get("Link"); !strings.Contains(got, `</_frame/a/assets/preload.js>`) {
		t.Fatalf("frame Link = %q", got)
	}
	if got := resp.Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("frame Set-Cookie leaked: %q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("frame Cache-Control = %q", got)
	}
	if got := resp.Header.Get("Service-Worker-Allowed"); got != "/_frame/a/" {
		t.Fatalf("frame Service-Worker-Allowed = %q", got)
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
	if !strings.Contains(body, "src=`https://claude.example`") {
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
	if got := resp.Header.Get("Cache-Control"); got != "private, no-store" {
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
func TestParseCookieHeaderPreservesPlusInAccountEmail(t *testing.T) {
	cookies := parseCookieHeader("pool_acct=user+artifact%40example.com; pool_parent=https%3A%2F%2Fclaude.example")
	if got, want := cookies["pool_acct"], "user+artifact@example.com"; got != want {
		t.Fatalf("pool_acct = %q, want %q", got, want)
	}
	if got, want := cookies[sandboxParentCookieName], "https://claude.example"; got != want {
		t.Fatalf("pool_parent = %q, want %q", got, want)
	}
}

func TestRewriteLegacyRootNextURLs(t *testing.T) {
	input := `href="/_next/static/site.css" src=/_next/static/app.js css=url(/_next/static/site.css) link=</_next/static/preload.js>; rel=preload location=/_next?x=1 hash=/_next#section json="\/_next\/static\/app.js" unicode="\u002F_next\u002Fstatic\u002Fapp.js" hex="\x2F_next\x2Fstatic\x2Fapp.js" already="/_uc/_next/ready.js" lookalike="/_nextish/app.js" absolute="https://a.claude.ai/_next/app.js" protocol="//a.claude.ai/_next/app.js"`
	got := rewriteLegacyRootNextURLs(input)
	for _, want := range []string{
		`href="/_uc/_next/static/site.css"`,
		`src=/_uc/_next/static/app.js`,
		`url(/_uc/_next/static/site.css)`,
		`</_uc/_next/static/preload.js>`,
		`location=/_uc/_next?x=1`,
		`hash=/_uc/_next#section`,
		`json="\/_uc\/_next\/static\/app.js"`,
		`unicode="\u002F_uc\u002F_next\u002Fstatic\u002Fapp.js"`,
		`hex="\x2F_uc\x2F_next\x2Fstatic\x2Fapp.js"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("legacy Next rewrite missing %q: %q", want, got)
		}
	}
	for _, want := range []string{
		`/_uc/_next/ready.js`,
		`/_nextish/app.js`,
		`https://a.claude.ai/_next/app.js`,
		`//a.claude.ai/_next/app.js`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("legacy Next rewrite changed %q: %q", want, got)
		}
	}
	if again := rewriteLegacyRootNextURLs(got); again != got {
		t.Fatalf("legacy Next rewrite was not idempotent: %q", again)
	}
}

func TestLegacySandboxResponseNamespacesRootNextAssets(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://claudeapi.example/_uc?domain=claude.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, &proxyCtx{
		mainOrig:     "https://claude.example",
		artifactOrig: "https://claudeapi.example",
		ucOrig:       "https://claudeapi.example/_uc",
		legacy:       true,
	}))
	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"text/html; charset=utf-8"},
			"Link":         []string{`</_next/static/preload.js>; rel=preload`},
			"Location":     []string{"/_next/static/redirect.js"},
		},
		Body:    io.NopCloser(strings.NewReader(`<link href="/_next/static/site.css"><script src="/_next/static/app.js"></script>`)),
		Request: req,
	}
	if err := proxyModifyResponse(resp); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); !strings.Contains(got, `/_uc/_next/static/site.css`) || !strings.Contains(got, `/_uc/_next/static/app.js`) {
		t.Fatalf("legacy body did not namespace Next assets: %q", got)
	}
	if got := resp.Header.Get("Link"); !strings.Contains(got, `</_uc/_next/static/preload.js>`) {
		t.Fatalf("legacy Link header = %q", got)
	}
	if got := resp.Header.Get("Location"); got != "/_uc/_next/static/redirect.js" {
		t.Fatalf("legacy Location header = %q", got)
	}
}
