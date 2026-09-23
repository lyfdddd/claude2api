package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"claude2api/internal/config"
	"claude2api/internal/middleware"
	"claude2api/internal/repository"
	"claude2api/internal/service"
	"claude2api/internal/utils"

	"github.com/gin-gonic/gin"
)

const (
	upstreamHost = "claude.ai"
	assetsHost   = "assets-proxy.anthropic.com"
	ucHost       = "www.claudeusercontent.com"
	artifactHost = "a.claude.ai"
	authPrefix   = "/__auth/"
	ucPathPrefix = "/_uc"
	authAcctPath = "__acct/"
)

// 转发到上游的请求头白名单。
var forwardReqHeaders = map[string]bool{
	"accept": true, "accept-language": true, "content-type": true, "user-agent": true,
	"anthropic-client-platform": true, "anthropic-client-version": true,
	"anthropic-client-sha": true, "anthropic-anonymous-id": true, "anthropic-device-id": true,
	"x-requested-with": true, "sec-fetch-dest": true, "sec-fetch-mode": true, "sec-fetch-site": true,
}

// 上游响应头黑名单。
var stripRespHeaders = map[string]bool{
	"content-encoding": true, "content-length": true, "transfer-encoding": true,
	"connection": true, "content-security-policy": true,
	"content-security-policy-report-only": true, "x-frame-options": true,
	"strict-transport-security": true, "report-to": true, "nel": true, "alt-svc": true,
}

// 需要改写 body 的内容类型。
var rewriteCT = []string{"text/html", "application/javascript", "text/javascript",
	"application/json", "text/css"}

// proxyCtx 供 Director 和 ModifyResponse 共享。
type proxyCtx struct {
	record           *repository.Account
	email            string
	browserCookies   string
	downstreamHTTPS  bool
	artifactTicketed bool
	onMain           bool
	mainOrig         string
	artifactOrig     string
	ucOrig           string
	artifact         bool
}

type ctxKey struct{}

var newProxy = buildReverseProxy()

// buildReverseProxy 构造共享反代。
func buildReverseProxy() *httputil.ReverseProxy {
	rp := &httputil.ReverseProxy{
		Transport:      service.NewProxyRoundTripper(),
		FlushInterval:  -1,
		Director:       proxyDirector,
		ModifyResponse: proxyModifyResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) || errors.Is(err, http.ErrAbortHandler) {
				return
			}
			slog.Error("[反代] 上游请求失败", "method", r.Method, "url", r.URL.String(), "err", err)
			http.Error(w, fmt.Sprintf("upstream error: %s", utils.Truncate(err.Error(), 100)), http.StatusBadGateway)
		},
	}
	return rp
}

// proxyDirector 改写上游请求。
func proxyDirector(req *http.Request) {
	pc, _ := req.Context().Value(ctxKey{}).(*proxyCtx)
	if pc == nil {
		return
	}
	path := req.URL.Path

	orig := req.Header.Clone()

	targetHost, scheme := proxyTarget(path, pc.onMain, pc.artifact)

	req.URL.Scheme = scheme
	req.URL.Host = targetHost
	req.Host = targetHost

	req.Header = http.Header{}
	for k, v := range service.BuildHeaders(pc.email) {
		req.Header.Set(k, v)
	}
	for k, vs := range orig {
		if forwardReqHeaders[strings.ToLower(k)] {
			for _, v := range vs {
				req.Header.Set(k, v)
			}
		}
	}
	originURL := scheme + "://" + targetHost
	req.Header.Set("origin", originURL)
	req.Header.Set("referer", originURL+"/")
	req.Header.Set("cookie", mergeProxyCookies(pc.browserCookies, cookieHeader(pc.record)))
}

func proxyTarget(path string, onMain, artifact bool) (string, string) {
	switch {
	case !onMain && artifact:
		return artifactHost, "https"
	case !onMain:
		return ucHost, "https"
	case isArtifactNavigation(path):
		return artifactHost, "https"
	case strings.HasPrefix(path, "/claude-ai/") || strings.HasPrefix(path, "/api/assets/"):
		return assetsHost, "https"
	default:
		return upstreamHost, "https"
	}
}

func hasPathPrefix(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func isArtifactNavigation(path string) bool {
	return hasPathPrefix(path, "/code/artifact")
}

// sandboxUpstreamPath distinguishes legacy Claudeusercontent requests from
// Artifact SPA requests on the sandbox host.
func sandboxUpstreamPath(path string) (string, bool) {
	if !hasPathPrefix(path, ucPathPrefix) {
		return path, true
	}
	path = strings.TrimPrefix(path, ucPathPrefix)
	if path == "" {
		path = "/"
	}
	return path, false
}

// maxRewriteBody 是 body 改写上限。
const maxRewriteBody = 10 << 20

type readCloserPair struct {
	io.Reader
	io.Closer
}

// proxyModifyResponse 改写上游响应。
func proxyModifyResponse(resp *http.Response) error {
	pc, _ := resp.Request.Context().Value(ctxKey{}).(*proxyCtx)
	if pc == nil {
		return nil
	}
	ct := resp.Header.Get("content-type")
	isStream := strings.Contains(ct, "text/event-stream")
	if pc.artifactTicketed {
		resp.Header.Set("Cache-Control", "no-store")
	}

	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	for _, k := range keys {
		lk := strings.ToLower(k)
		if stripRespHeaders[lk] {
			resp.Header.Del(k)
			continue
		}
		if lk == "location" {
			v := resp.Header.Get(k)
			// /login 重定向短窗口内二次确认后才标失效。
			if pc.onMain && isLoginRedirect(v) {
				if confirmLoginExpired(pc.email) {
					repository.UpdateAccount(pc.email, func(a *repository.Account) { a.Status = "expired" })
					slog.Warn("[号池] 账号会话失效（二次确认），已踢回选择页", "email", pc.email)
				} else {
					slog.Info("[号池] 账号疑似会话失效（首次 /login 重定向），暂不标记", "email", pc.email)
				}
				resp.Header.Set(k, "/")
				resp.Header.Add("Set-Cookie", "pool_acct=; Path=/; Max-Age=0")
				continue
			}
			resp.Header.Set(k, rewriteResponseURL(v, pc.mainOrig, pc.artifactOrig, pc.ucOrig))
		} else if lk == "link" {
			vals := resp.Header.Values(k)
			resp.Header.Del(k)
			for _, v := range vals {
				resp.Header.Add(k, rewriteResponseURL(v, pc.mainOrig, pc.artifactOrig, pc.ucOrig))
			}
		} else if lk == "set-cookie" {
			vals := resp.Header.Values(k)
			resp.Header.Del(k)
			for _, v := range vals {
				resp.Header.Add(k, rewriteProxySetCookie(v, pc.downstreamHTTPS))
			}
		}
	}

	if isStream {
		resp.Header.Set("Cache-Control", "no-cache")
		return nil
	}

	needRewrite := false
	for _, t := range rewriteCT {
		if strings.Contains(ct, t) {
			needRewrite = true
			break
		}
	}
	injectBar := pc.onMain && strings.Contains(ct, "text/html")
	if !needRewrite && !injectBar {
		return nil
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRewriteBody+1))
	if err != nil {
		resp.Body.Close()
		return err
	}
	if len(data) > maxRewriteBody {
		// 超限时拼回已读内容并透传。
		slog.Info("[反代] 响应过大，跳过域名改写直接透传", "limit_mb", maxRewriteBody>>20, "content_type", ct)
		resp.Body = readCloserPair{io.MultiReader(bytes.NewReader(data), resp.Body), resp.Body}
		return nil
	}
	resp.Body.Close()
	if needRewrite {
		data = rewriteBody(data, pc.mainOrig, pc.artifactOrig, pc.ucOrig)
	}
	if injectBar {
		data = injectPoolBar(data, pc.email)
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))
	resp.ContentLength = int64(len(data))
	return nil
}

var domainStripRe = regexp.MustCompile(`;\s*[Dd]omain=[^;]+`)

var artifactTargetOriginRe = regexp.MustCompile(`(?i)(["']?targetOrigin["']?\s*[:=]\s*["'])https://a\.claude\.ai/?(["'])`)

func rewriteResponseURL(value, mainOrigin, artifactOrigin, ucOrigin string) string {
	value = rewriteURLHost(value, ucHost, ucOrigin)
	value = rewriteURLHost(value, "claudeusercontent.com", ucOrigin)
	value = rewriteURLHost(value, artifactHost, artifactOrigin)
	value = rewriteURLHost(value, upstreamHost, mainOrigin)
	return value
}

// rewriteURLHost changes absolute and protocol-relative URL references. It is
// used for response headers, where every host reference is a navigable URL.
func rewriteURLHost(value, sourceHost, target string) string {
	value = rewriteURLHostPaths(value, sourceHost, target)
	return rewriteBareURLHost(value, sourceHost, target)
}

func rewriteBareURLHost(value, sourceHost, target string) string {
	for _, suffix := range []string{`"`, `'`, "`", " ", "\t", "\r", "\n", ")", "]", "}", ",", ";", "<", ">"} {
		value = strings.ReplaceAll(value, "https://"+sourceHost+suffix, target+suffix)
		value = strings.ReplaceAll(value, "//"+sourceHost+suffix, "//"+originNetloc(target)+suffix)
	}
	if strings.HasSuffix(value, "https://"+sourceHost) {
		value = strings.TrimSuffix(value, "https://"+sourceHost) + target
	}
	if strings.HasSuffix(value, "//"+sourceHost) {
		value = strings.TrimSuffix(value, "//"+sourceHost) + "//" + originNetloc(target)
	}
	return value
}

func rewriteURLHostPaths(value, sourceHost, target string) string {
	targetNet := originNetloc(target)
	for _, suffix := range []string{"/", "?", "#"} {
		value = strings.ReplaceAll(value, "https://"+sourceHost+suffix, target+suffix)
		value = strings.ReplaceAll(value, "//"+sourceHost+suffix, "//"+targetNet+suffix)
	}
	return value
}

// rewriteArtifactBodyURLs keeps resource URLs on the ticketed sandbox entry,
// but preserves a clean origin for postMessage targetOrigin comparisons.
func rewriteArtifactBodyURLs(value, artifactURLBase string) string {
	sandboxOrigin := originOnly(artifactURLBase)
	value = artifactTargetOriginRe.ReplaceAllString(value, "${1}"+sandboxOrigin+"${2}")
	value = rewriteURLHostPaths(value, artifactHost, artifactURLBase)
	return rewriteBareURLHost(value, artifactHost, sandboxOrigin)
}

func originOnly(value string) string {
	u, err := url.Parse(value)
	if err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return value
}

func originNetloc(origin string) string {
	if parts := strings.SplitN(origin, "//", 2); len(parts) == 2 {
		return parts[1]
	}
	return origin
}

var (
	loginSuspectLock sync.Mutex
	loginSuspect     = map[string]time.Time{}
)

const loginSuspectWindow = 10 * time.Minute

const sandboxParentCookieName = "pool_parent"

type artifactTicket struct {
	credential string
	email      string
	mainOrigin string
	expires    time.Time
}

var artifactTickets = struct {
	sync.Mutex
	items map[string]artifactTicket
}{items: map[string]artifactTicket{}}

func issueArtifactTicket(credential, email, mainOrigin string) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	now := time.Now()
	token := base64.RawURLEncoding.EncodeToString(b)
	artifactTickets.Lock()
	for key, ticket := range artifactTickets.items {
		if now.After(ticket.expires) {
			delete(artifactTickets.items, key)
		}
	}
	artifactTickets.items[token] = artifactTicket{credential: credential, email: email, mainOrigin: originOnly(mainOrigin), expires: now.Add(10 * time.Minute)}
	artifactTickets.Unlock()
	return token, nil
}

func artifactTicketForPath(path string) (artifactTicket, string, bool) {
	token, cleanPath, ok := artifactTicketPath(path)
	if !ok {
		return artifactTicket{}, "", false
	}
	artifactTickets.Lock()
	ticket, found := artifactTickets.items[token]
	if found && time.Now().After(ticket.expires) {
		delete(artifactTickets.items, token)
		found = false
	}
	artifactTickets.Unlock()
	if !found {
		return artifactTicket{}, "", false
	}
	return ticket, cleanPath, true
}

func artifactTicketPath(path string) (string, string, bool) {
	if !strings.HasPrefix(path, authPrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(path, authPrefix)
	token, cleanPath, _ := strings.Cut(rest, "/")
	if token == "" {
		return "", "", false
	}
	return token, "/" + cleanPath, true
}

// confirmLoginExpired 二次确认 /login 重定向。
func confirmLoginExpired(email string) bool {
	now := time.Now()
	loginSuspectLock.Lock()
	defer loginSuspectLock.Unlock()
	if t, ok := loginSuspect[email]; ok && now.Sub(t) <= loginSuspectWindow {
		delete(loginSuspect, email)
		return true
	}
	loginSuspect[email] = now
	return false
}

// isLoginRedirect 只识别 /login。
func isLoginRedirect(loc string) bool {
	if loc == "" {
		return false
	}
	low := strings.ToLower(loc)
	return strings.HasPrefix(low, "/login") ||
		strings.Contains(low, "claude.ai/login")
}

// ServeMainProxy 处理主站反代。
func ServeMainProxy(c *gin.Context) {
	ServeReverseProxy(c.Writer, c.Request, true)
}

// ServeUCProxy 处理 artifact 反代。
func ServeUCProxy(c *gin.Context) {
	ServeReverseProxy(c.Writer, c.Request, false)
}

// ServeReverseProxy 是反代入口。
func ServeReverseProxy(w http.ResponseWriter, r *http.Request, onMain bool) {
	downstreamHTTPS := requestScheme(r) == "https"
	credential := middleware.ValidPoolRequestCredential(r)
	if onMain {
		if credential == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}
	if !onMain {
		if ticket, cleanPath, ok := artifactTicketForPath(r.URL.EscapedPath()); ok {
			if !middleware.PoolCredentialValid(ticket.credential) {
				if credential != "" {
					w.Header().Set("Cache-Control", "no-store")
					http.Redirect(w, r, sandboxRedirectURL(requestOrigin(r), cleanPath, r.URL), http.StatusTemporaryRedirect)
					return
				}
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			middleware.SetAuthResponseCookie(w, r, ticket.credential)
			setSandboxTicketCookies(w, ticket, downstreamHTTPS)
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, sandboxRedirectURL(requestOrigin(r), cleanPath, r.URL), http.StatusTemporaryRedirect)
			return
		} else if _, cleanPath, ticketed := artifactTicketPath(r.URL.EscapedPath()); ticketed && credential != "" {
			// An authenticated sandbox may encounter an expired ticket in a
			// restored browser tab. Drop the ticket rather than proxying it upstream.
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, sandboxRedirectURL(requestOrigin(r), cleanPath, r.URL), http.StatusTemporaryRedirect)
			return
		} else if credential == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	browserCookies := parseCookieHeader(r.Header.Get("Cookie"))
	selected := browserCookies["pool_acct"]
	record := service.AccountByEmail(selected)

	if onMain {
		if record == nil {
			if selected != "" {
				http.SetCookie(w, &http.Cookie{Name: "pool_acct", Value: "", Path: "/", MaxAge: -1})
			}
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}
	if record == nil {
		http.Error(w, "no selected account", http.StatusUnauthorized)
		return
	}
	email := record.Email
	mainOrig := requestOrigin(r)
	artifactOrig := artifactOrigin(r)
	ucOrig := strings.TrimRight(artifactOrig, "/") + ucPathPrefix
	artifact := false
	artifactTicketed := false
	if onMain {
		ticket, err := issueArtifactTicket(credential, email, mainOrig)
		if err != nil {
			http.Error(w, "artifact authorization unavailable", http.StatusInternalServerError)
			return
		}
		artifactOrig += authPrefix + ticket
		ucOrig = artifactOrig + ucPathPrefix
		artifactTicketed = true
		w.Header().Set("Cache-Control", "no-store")
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && isArtifactNavigation(r.URL.Path) {
			http.Redirect(w, r, artifactRedirectURL(artifactOrig, r.URL), http.StatusFound)
			return
		}
	}
	if !onMain {
		artifactOrig = requestOrigin(r)
		ucOrig = strings.TrimRight(artifactOrig, "/") + ucPathPrefix
		mainOrig = sandboxParentOrigin(browserCookies, r)
		upstreamPath, isArtifact := sandboxUpstreamPath(r.URL.Path)
		if upstreamPath != r.URL.Path {
			r.URL.Path = upstreamPath
			r.URL.RawPath = ""
		}
		artifact = isArtifact
	}
	pc := &proxyCtx{
		record:           record,
		email:            email,
		browserCookies:   r.Header.Get("Cookie"),
		downstreamHTTPS:  downstreamHTTPS,
		artifactTicketed: artifactTicketed,
		onMain:           onMain,
		mainOrig:         mainOrig,
		artifactOrig:     artifactOrig,
		ucOrig:           ucOrig,
		artifact:         artifact,
	}
	ctx := context.WithValue(r.Context(), ctxKey{}, pc)
	defer func() {
		if v := recover(); v != nil {
			if v == http.ErrAbortHandler {
				return
			}
			panic(v)
		}
	}()
	newProxy.ServeHTTP(w, r.WithContext(ctx))
}

func setSandboxTicketCookies(w http.ResponseWriter, ticket artifactTicket, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: "pool_acct", Value: ticket.email, Path: "/", MaxAge: 31536000,
		Secure: secure, SameSite: http.SameSiteLaxMode,
	})
	if parent := validHTTPOrigin(ticket.mainOrigin); parent != "" {
		http.SetCookie(w, &http.Cookie{
			Name: sandboxParentCookieName, Value: url.QueryEscape(parent), Path: "/", MaxAge: 86400,
			Secure: secure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
	}
}

func sandboxParentOrigin(cookies map[string]string, r *http.Request) string {
	if parent := validHTTPOrigin(cookies[sandboxParentCookieName]); parent != "" {
		return parent
	}
	return requestOrigin(r)
}

func validHTTPOrigin(value string) string {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func sandboxRedirectURL(sandboxOrigin, cleanPath string, requestURL *url.URL) string {
	target := strings.TrimRight(sandboxOrigin, "/") + cleanPath
	if requestURL.ForceQuery || requestURL.RawQuery != "" {
		target += "?" + requestURL.RawQuery
	}
	return target
}

func artifactRedirectURL(ucOrigin string, requestURL *url.URL) string {
	target := ucOrigin + requestURL.EscapedPath()
	if requestURL.ForceQuery || requestURL.RawQuery != "" {
		target += "?" + requestURL.RawQuery
	}
	return target
}

// IsUCHost 判断 artifact Host。
func IsUCHost(hostport string) bool {
	host := hostname(hostport)
	if configured := hostname(config.Get().WebUCHost); configured != "" {
		return strings.EqualFold(host, configured)
	}
	return strings.EqualFold(host, "localhost") || strings.HasPrefix(strings.ToLower(host), "uc.")
}

func artifactOrigin(r *http.Request) string {
	scheme := requestScheme(r)
	mainHost := hostname(r.Host)
	ucHostName := hostname(config.Get().WebUCHost)
	if ucHostName == "" {
		if mainHost == "127.0.0.1" || mainHost == "::1" {
			ucHostName = "localhost"
		} else {
			ucHostName = "uc." + mainHost
		}
	}
	if port := requestPort(r.Host); port != "" {
		ucHostName = net.JoinHostPort(ucHostName, port)
	}
	return scheme + "://" + ucHostName
}

func requestOrigin(r *http.Request) string {
	return requestScheme(r) + "://" + r.Host
}

func requestScheme(r *http.Request) string {
	scheme := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}
	return scheme
}

func hostname(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return strings.Trim(hostport, "[]")
}

func requestPort(hostport string) string {
	_, port, _ := net.SplitHostPort(hostport)
	return port
}

var skipAccountCookies = map[string]bool{
	"cf_clearance": true,
	"__cf_bm":      true,
}

func cookieHeader(record *repository.Account) string {
	ck := record.Cookies
	parts := make([]string, 0, len(ck))
	for k, v := range ck {
		if skipAccountCookies[k] {
			continue
		}
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, "; ")
}

func mergeProxyCookies(browser, account string) string {
	merged := map[string]string{}
	for _, header := range []string{browser, account} {
		for _, part := range strings.Split(header, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok && name != middleware.AuthCookieName && name != "pool_acct" && name != "pool_cid" && name != "mirror" && name != sandboxParentCookieName {
				merged[name] = value
			}
		}
	}
	parts := make([]string, 0, len(merged))
	for name, value := range merged {
		parts = append(parts, name+"="+value)
	}
	return strings.Join(parts, "; ")
}

// parseCookieHeader 解析 Cookie，并还原百分号编码值。
func parseCookieHeader(header string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(header, ";") {
		if i := strings.IndexByte(part, '='); i >= 0 {
			key := strings.TrimSpace(part[:i])
			val := strings.TrimSpace(part[i+1:])
			if dec, err := url.PathUnescape(val); err == nil {
				val = dec
			}
			out[key] = val
		}
	}
	return out
}

// rewriteBody 改写官网域名。
func rewriteBody(data []byte, mainOrigin, artifactOrigin, ucOrigin string) []byte {
	text := string(data)
	text = rewriteURLHost(text, ucHost, ucOrigin)
	text = rewriteURLHost(text, "claudeusercontent.com", ucOrigin)
	text = rewriteArtifactBodyURLs(text, artifactOrigin)
	mainNet := mainOrigin
	if p := strings.SplitN(mainOrigin, "//", 2); len(p) == 2 {
		mainNet = p[1]
	}
	text = strings.ReplaceAll(text, "https://"+assetsHost, mainOrigin)
	text = strings.ReplaceAll(text, "https://"+upstreamHost, mainOrigin)
	text = strings.ReplaceAll(text, "//"+upstreamHost, "//"+mainNet)
	return []byte(text)
}

// injectPoolBar 注入账号浮条。
func injectPoolBar(data []byte, email string) []byte {
	text := string(data)
	if !strings.Contains(text, "</body>") {
		return data
	}
	safeEmail := html.EscapeString(email)
	if safeEmail == "" {
		safeEmail = "—"
	}

	bar := `<div id="__pool_bar__" class="pb-card">` +
		`<span class="pb-acct" title="` + safeEmail + `">` +
		`<span class="pb-label">账号</span>` +
		`<b class="pb-email">` + safeEmail + `</b></span>` +
		`<a class="pb-switch" href="/">切换账号</a>` +
		`</div>`

	css := `<style>` +
		`#__pool_bar__.pb-card{position:fixed;right:14px;top:14px;z-index:2147483647;` +
		`display:flex;align-items:center;gap:9px;max-width:360px;box-sizing:border-box;` +
		`padding:9px 11px;` +
		`font:12px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;` +
		`color:#3d3a34;background:rgba(252,251,248,.92);` +
		`-webkit-backdrop-filter:saturate(1.4) blur(10px);backdrop-filter:saturate(1.4) blur(10px);` +
		`border:1px solid #e7e3da;border-radius:12px;` +
		`box-shadow:0 6px 24px -6px rgba(60,50,30,.18),0 1px 3px rgba(60,50,30,.08);` +
		`animation:pbin .28s cubic-bezier(.2,.8,.3,1)}` +
		`@keyframes pbin{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:none}}` +
		`#__pool_bar__ .pb-acct{display:flex;align-items:baseline;gap:5px;min-width:0}` +
		`#__pool_bar__ .pb-label{color:#9a968c;flex:none}` +
		`#__pool_bar__ .pb-email{font-weight:600;color:#1f1e1c;white-space:nowrap;overflow:hidden;` +
		`text-overflow:ellipsis;min-width:0}` +
		`#__pool_bar__ .pb-switch{flex:none;color:#c96442;font-weight:600;text-decoration:none;` +
		`padding:3px 9px;border-radius:7px;transition:background .15s}` +
		`#__pool_bar__ .pb-switch:hover{background:rgba(201,100,66,.1)}` +
		`</style>`

	text = strings.Replace(text, "</body>", css+bar+"</body>", 1)
	return []byte(text)
}
func rewriteProxySetCookie(value string, keepSecure bool) string {
	value = domainStripRe.ReplaceAllString(value, "")
	if !keepSecure {
		value = strings.ReplaceAll(value, "; Secure", "")
		value = strings.ReplaceAll(value, "; secure", "")
	}
	return value
}
