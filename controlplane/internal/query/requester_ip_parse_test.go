package query

import "testing"

// RequesterIpParseTest.kt — 2 cases, unit (counted in A12; the function is A6's).
//
// ParseRequesterIp extracts the bare IP from a proxy-supplied client_addr (Netty
// SocketAddress.toString()) for the Cedar `requester_ip`. Fail-closed — anything unparseable → nil
// (the attribute is then ABSENT, never malformed; A2 INV-A2-8).

func gotIP(t *testing.T, in string) string {
	t.Helper()
	v := ParseRequesterIp(&in)
	if v == nil {
		return "<nil>"
	}
	return *v
}

// `extracts the ip from Netty host-port forms`
func TestParseRequesterIpExtractsTheIPFromNettyHostPortForms(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/1.2.3.4:5432", "1.2.3.4"},
		{"/[::1]:5432", "::1"},
		{"/[2001:db8::1]:443", "2001:db8::1"},
		{"10.0.0.1:5432", "10.0.0.1"},
		{"192.168.1.1", "192.168.1.1"},
		{"/100.100.5.5:0", "100.100.5.5"},
	} {
		if got := gotIP(t, tc.in); got != tc.want {
			t.Errorf("ParseRequesterIp(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// `null blank empty or slash-only yield null — fail closed`
func TestParseRequesterIpNullBlankEmptyOrSlashOnlyYieldNil(t *testing.T) {
	if got := ParseRequesterIp(nil); got != nil {
		t.Errorf("ParseRequesterIp(nil) = %q, want nil", *got)
	}
	for _, in := range []string{"", "   ", "/"} {
		if got := gotIP(t, in); got != "<nil>" {
			t.Errorf("ParseRequesterIp(%q) = %q, want nil", in, got)
		}
	}
}

// The bracket and multi-colon branches, which 06-query-decision.md §7 lists as a COVERAGE GAP in the
// Kotlin suite ("only 2 cases … the bracket and multi-colon branches are thin"). These pin what the
// Kotlin's `substringAfter`/`substringBefore` actually do, so the Go port cannot drift into a
// stricter parser that starts returning nil where the Kotlin returned a value.
//
// ⚠️ The last two rows are the reason this function must stay DELIBERATELY LAXER than A12's
// stripToBareIp: it parses Netty's always-well-formed SocketAddress.toString(), and a residual non-IP
// survivor is dropped defensively at AuthzContext.ToCedarMap. Do not unify the two without
// re-checking that assumption (A12 Q4).
func TestParseRequesterIpBracketAndMultiColonBranches(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		// A bare v6 has more than one ':' and takes the "else" arm untouched.
		{"bare v6, no port", "2001:db8::1", "2001:db8::1"},
		// Kotlin's substringBefore returns the WHOLE remainder when ']' is absent.
		{"unterminated bracket keeps the remainder", "/[::1", "::1"},
		// Kotlin's substringAfter('[') on a value whose '[' is not leading is unreachable: the branch
		// is chosen by startsWith("["). "a[b" has one ':'? No — zero, so it is bare.
		{"no colon at all is bare", "not-an-ip", "not-an-ip"},
		// Exactly one ':' takes the v4:port arm even when the left side is not a v4 literal.
		{"one colon splits regardless of shape", "host:5432", "host"},
		// An empty left side of a single ':' yields "" → nil (the trailing takeIf).
		{"empty left of a single colon is nil", ":5432", "<nil>"},
		// "[]" yields "" between the brackets → nil.
		{"empty brackets are nil", "/[]:5432", "<nil>"},
	} {
		if got := gotIP(t, tc.in); got != tc.want {
			t.Errorf("%s: ParseRequesterIp(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}
