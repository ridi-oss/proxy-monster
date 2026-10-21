package oidc

import "testing"

func TestReturnTarget(t *testing.T) {
	for _, ok := range []string{"/oauth/resume", "/auth/reauth-complete", "/device", "/device?user_code=ABCD-EFGH"} {
		if got := returnTarget(ok); got == nil || *got != ok {
			t.Errorf("%s dropped", ok)
		}
	}
	for _, bad := range []string{
		"/auth/device/authorize?user_code=ABCD-EFGH", "https://evil.example/device", "//evil.example/device", "/device/other",
		"/device?foo=bar", "/device?user_code=ABCD-EFGH&next=https://evil.example", "/auth/device/authorize?user_code=ABCD-EFGH&extra=x",
		"/other", "/",
	} {
		if got := returnTarget(bad); got != nil {
			t.Errorf("%s kept as %s", bad, *got)
		}
	}
}
