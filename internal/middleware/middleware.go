package middleware

import (
	"net/http"
	"strings"

	"claude2api/internal/config"
	"claude2api/internal/repository"

	"github.com/gin-gonic/gin"
)

const AuthCookieName = "claude2api_auth"

// AdminAuth 保护管理 API。
func AdminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := c.Request.URL.Path
		if p == "/api/login" || p == "/api/logout" {
			c.Next()
			return
		}
		credential := bearerToken(c.GetHeader("Authorization"))
		if AdminCredentialValid(credential) {
			c.Next()
			return
		}
		if !strings.Contains(p, "/api/") {
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "未登录或密码错误"})
	}
}

// PoolAuth 保护号池页面和接口。
func PoolAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		credential := ValidPoolRequestCredential(c.Request)
		if credential != "" {
			if authorization := bearerToken(c.GetHeader("Authorization")); PoolCredentialValid(authorization) {
				SetAuthCookie(c, credential)
			}
			c.Next()
			return
		}
		if !strings.Contains(c.Request.URL.Path, "/api/") {
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or missing pool key"})
	}
}

// SetAuthCookie 保存登录凭据。
func SetAuthCookie(c *gin.Context, credential string) {
	secure := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
	c.SetCookie(AuthCookieName, credential, 86400, "/", "", secure, true)
}

func ClearAuthCookie(c *gin.Context) {
	secure := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
	c.SetCookie(AuthCookieName, "", -1, "/", "", secure, true)
}

// SetAuthResponseCookie 同步 artifact 登录凭据。
func SetAuthResponseCookie(w http.ResponseWriter, r *http.Request, credential string) {
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name: AuthCookieName, Value: credential, Path: "/", MaxAge: 86400,
		Secure: secure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// RequestCredential 读取首个 Bearer 或 Cookie。调用方若要做号池鉴权，
// 应使用 ValidPoolRequestCredential，以免无效 Authorization 遮蔽有效 Cookie。
func RequestCredential(r *http.Request) string {
	if credential := bearerToken(r.Header.Get("Authorization")); credential != "" {
		return credential
	}
	cookie, err := r.Cookie(AuthCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// ValidPoolRequestCredential 从请求中的所有候选凭据里选择有效凭据。
// Artifact 上游可能带有与本站无关的 Authorization，不能让它覆盖浏览器
// 已携带的本站 Cookie；同名旧 Cookie 也要逐个校验。
func ValidPoolRequestCredential(r *http.Request) string {
	return firstValidCredential(requestCredentialCandidates(r), PoolCredentialValid)
}

const maxPoolCredentialCandidates = 8

func requestCredentialCandidates(r *http.Request) []string {
	candidates := make([]string, 0, maxPoolCredentialCandidates)
	seen := make(map[string]struct{}, maxPoolCredentialCandidates)
	appendCandidate := func(credential string) {
		if credential == "" || len(candidates) == maxPoolCredentialCandidates {
			return
		}
		if _, exists := seen[credential]; exists {
			return
		}
		seen[credential] = struct{}{}
		candidates = append(candidates, credential)
	}

	appendCandidate(bearerToken(r.Header.Get("Authorization")))
	for _, cookie := range r.Cookies() {
		if len(candidates) == maxPoolCredentialCandidates {
			break
		}
		if cookie.Name == AuthCookieName {
			appendCandidate(cookie.Value)
		}
	}
	return candidates
}

func firstValidCredential(candidates []string, valid func(string) bool) string {
	for _, credential := range candidates {
		if valid(credential) {
			return credential
		}
	}
	return ""
}

func AdminCredentialValid(credential string) bool {
	pw := config.Get().AdminPassword
	return pw != "" && credential == pw
}

func PoolCredentialValid(credential string) bool {
	return AdminCredentialValid(credential) || repository.ValidateAPIKey(credential)
}

// APIKey 保护 2api。
func APIKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := bearerToken(c.GetHeader("Authorization"))
		if token == "" {
			token = strings.TrimSpace(c.GetHeader("x-api-key"))
		}
		// 后台在线测试可复用管理密码。
		if pw := config.Get().AdminPassword; pw != "" && token == pw {
			c.Next()
			return
		}
		if repository.ValidateAPIKey(token) {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": gin.H{"message": "无效的 API 密钥", "type": "invalid_request_error"},
		})
	}
}

// bearerToken 解析 Bearer token。
func bearerToken(h string) string {
	h = strings.TrimSpace(h)
	if len(h) >= 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return h
}
