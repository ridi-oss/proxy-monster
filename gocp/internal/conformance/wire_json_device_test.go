package conformance

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/device"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ============================================================================================
// CONTRACT 3 (continued) — the five RFC 8628 device-authorization DTOs. INV-A1-4.
//
// ORACLE: 04-auth-session-tokens.md §1.1's field table, whose source file header calls itself the
// "SHARED CONTRACT REGISTRY — pmon + web consume these". Every name, order and optionality below is
// read off that table.
//
// Why these need golden BYTES and not just unit assertions: three of the five carry a kotlinx DEFAULT
// on a NON-NULLABLE field (`DeviceConfirmAck.ok = true`, `DevicePollPending.status =
// "authorization_pending"`), and `encodeDefaults = true` means those are EMITTED. Go's two obvious
// spellings both get it wrong — `omitempty` drops `ok:false` and `status:""`, and no-omitempty on a
// zero value emits the wrong VALUE. Only "no omitempty AND a constructor that sets the default" is
// correct, and only literal bytes catch the difference.
//
// The other half is `pmon`. It is a Go client that decodes these with encoding/json, so a renamed or
// reordered key is not a console cosmetic — it is a login that stops working with no server-side
// signal, which is the same failure mode A11's Zod schemas produced (01-bootstrap.md quotes it).
// ============================================================================================

// --- device.StartResponse ---------------------------------------------------------------------
//
// All five fields are non-null with no default, so all five are always present. `interval` is an Int
// and must stay a JSON number, not a string.
func TestDeviceStartResponseGoldenBytes(t *testing.T) {
	assertWireBytes(t, device.StartResponse{
		VerificationURI:         "https://console.example/device",
		VerificationURIComplete: "https://console.example/device?user_code=WDJB-MJHT",
		UserCode:                "WDJB-MJHT",
		Handle:                  "dvc_0123456789abcdefghijklmnopqrstuv",
		Interval:                2,
	}, "device_start_response.json")
}

// --- device.ConfirmAck ------------------------------------------------------------------------
//
// 🔒 `ok: Boolean = true` — a kotlinx default on a NON-nullable field, so `encodeDefaults = true`
// EMITS it. [device.NewConfirmAck] is the only correct construction; the zero value is a different
// body.
func TestDeviceConfirmAckGoldenBytes(t *testing.T) {
	assertWireBytes(t, device.NewConfirmAck(), "device_confirm_ack.json")

	t.Run("the zero value is a DIFFERENT body, which is why the constructor exists", func(t *testing.T) {
		got, err := types.MarshalWire(device.ConfirmAck{})
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `{"ok":false}` {
			t.Fatalf("zero-value ConfirmAck = %s, want {\"ok\":false}", got)
		}
		// …and it must still carry the KEY. An `omitempty` here would emit `{}`, which the web
		// /device page parses as a successful confirm with no acknowledgement field at all.
		if !strings.Contains(string(got), `"ok"`) {
			t.Error("the `ok` key vanished — omitempty was added to a non-nullable field")
		}
	})
}

// --- device.PollPending -----------------------------------------------------------------------
//
// 🔒 Same defaulted-constant shape. The value is RFC 8628 §3.5's `authorization_pending`, and it is
// what pmon's poll loop branches on: a `{}` or `{"status":""}` body makes the daemon treat a pending
// login as an unknown state.
func TestDevicePollPendingGoldenBytes(t *testing.T) {
	assertWireBytes(t, device.NewPollPending(), "device_poll_pending.json")

	if device.AuthorizationPending != "authorization_pending" {
		t.Errorf("AuthorizationPending = %q — this string is RFC 8628 §3.5 and pmon's branch key",
			device.AuthorizationPending)
	}
}

// --- device.PollResult ------------------------------------------------------------------------
//
// 🔒 The ONE body that ever carries the `pmr_` renewal secret ("Returned EXACTLY ONCE, here").
//
// Both timestamps are Java `Instant.toString()` — VARIABLE fractional-second precision. The golden
// deliberately pairs a whole-second `expiresAt` with a millisecond `sessionExpiresAt`, because that
// is the pair a fixed-precision RFC3339 formatter would silently normalise into agreement.
func TestDevicePollResultGoldenBytes(t *testing.T) {
	assertWireBytes(t, device.PollResult{
		Token:            "pmt_0123456789abcdefghijklmnopqrstuvwxyzABCDEF",
		ExpiresAt:        "2026-08-02T03:04:05Z",
		Principal:        "alice@example.com",
		SessionExpiresAt: "2026-08-02T05:04:05.123Z",
		RenewalToken:     "pmr_ABCDEFghijklmnopqrstuvwxyz0123456789abcdef",
	}, "device_poll_result.json")
}

// --- device.StartInput / device.PollInput / device.ConfirmInput -------------------------------
//
// Inbound shapes: what `pmon` and the web /device page SEND. They get no golden file because nothing
// serialises them on the server — but the DECODE contract is still contract, and each of the three
// has a different strictness the routes depend on.
func TestDeviceInboundShapes(t *testing.T) {
	t.Run("StartInput.ttlSeconds is optional and absent-vs-null are the same", func(t *testing.T) {
		for _, body := range []string{`{}`, `{"ttlSeconds":null}`} {
			var in device.StartInput
			if err := json.Unmarshal([]byte(body), &in); err != nil {
				t.Fatalf("decode %s: %v", body, err)
			}
			if in.TTLSeconds != nil {
				t.Errorf("decode %s left ttlSeconds = %d, want nil", body, *in.TTLSeconds)
			}
		}
		var in device.StartInput
		if err := json.Unmarshal([]byte(`{"ttlSeconds":3600}`), &in); err != nil {
			t.Fatal(err)
		}
		if in.TTLSeconds == nil || *in.TTLSeconds != 3600 {
			t.Errorf("ttlSeconds = %v, want 3600", in.TTLSeconds)
		}
	})

	t.Run("StartInput round-trips as an empty object when unset", func(t *testing.T) {
		// The DEFAULTED input the route falls back to. `omitempty` on the pointer is what keeps this
		// `{}` rather than `{"ttlSeconds":null}` (INV-A1-4: explicitNulls = false).
		got, err := types.MarshalWire(device.StartInput{})
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `{}` {
			t.Fatalf("StartInput{} = %s, want {}", got)
		}
	})

	t.Run("PollInput and ConfirmInput carry exactly one required key each", func(t *testing.T) {
		var poll device.PollInput
		if err := json.Unmarshal([]byte(`{"handle":"dvc_abc"}`), &poll); err != nil {
			t.Fatal(err)
		}
		if poll.Handle != "dvc_abc" {
			t.Errorf("handle = %q", poll.Handle)
		}
		var confirm device.ConfirmInput
		if err := json.Unmarshal([]byte(`{"userCode":"WDJB-MJHT"}`), &confirm); err != nil {
			t.Fatal(err)
		}
		if confirm.UserCode != "WDJB-MJHT" {
			t.Errorf("userCode = %q", confirm.UserCode)
		}
	})
}

// --- 🔒 HTML escaping, on the field most likely to carry the characters -----------------------
//
// `verificationUriComplete` is a URL with a query string, and a split-origin deployment's
// PM_WEB_ORIGIN is operator-supplied. encoding/json rewrites `&` as & by default; kotlinx does
// not. That is the exact class of bug internal/conformance caught once already in QueryResponse.
func TestDeviceStartResponseIsNotHTMLEscaped(t *testing.T) {
	got, err := types.MarshalWire(device.StartResponse{
		VerificationURI:         "https://console.example/device",
		VerificationURIComplete: "https://console.example/device?user_code=WDJB-MJHT&next=/a<b>c",
		UserCode:                "WDJB-MJHT",
		Handle:                  "dvc_x",
		Interval:                2,
	})
	if err != nil {
		t.Fatal(err)
	}
	for raw, escaped := range htmlEscapes {
		if strings.Contains(string(got), escaped) {
			t.Errorf("%q was escaped to %q — MarshalWire must not HTML-escape", raw, escaped)
		}
	}
	if !strings.Contains(string(got), "&next=/a<b>c") {
		t.Errorf("the raw characters did not survive: %s", got)
	}
}
