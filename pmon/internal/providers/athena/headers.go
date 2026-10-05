package athena

import (
	"net/http"
	"strings"
)

func withoutHopHeaders(source http.Header) http.Header {
	header := source.Clone()
	for _, value := range source.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Proxy-Authenticate", "Proxy-Authorization"} {
		header.Del(name)
	}
	return header
}

func upstreamHeaders(source http.Header) http.Header {
	header := withoutHopHeaders(source)
	for name := range header {
		if credentialOrIdentityHeader(name) {
			header.Del(name)
		}
	}
	return header
}

func credentialOrIdentityHeader(name string) bool {
	name = strings.ToLower(name)
	for _, prefix := range []string{"x-pm-", "x-pmon-", "x-proxy-monster-", "x-forwarded-", "x-auth-request-", "x-amzn-oidc-", "x-amzn-mtls-"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	switch name {
	case "host", "content-length", "authorization", "cookie", "cookie2", "set-cookie",
		"forwarded", "x-real-ip", "x-client-ip", "client-ip", "true-client-ip", "x-original-forwarded-for",
		"cf-connecting-ip", "cf-connecting-ipv6", "remote-user", "x-remote-user", "x-authenticated-user", "x-authenticated-groups",
		"x-auth-token", "x-api-key", "date", "x-amz-date", "x-amz-security-token", "x-amz-content-sha256",
		"x-amz-algorithm", "x-amz-credential", "x-amz-signedheaders", "x-amz-signature", "x-amz-expires", "x-amz-region-set", "x-amz-sso-bearer-token":
		return true
	}
	return false
}
