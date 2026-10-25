package oauth

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

func TestTheConsentPageLabelsEveryScope(t *testing.T) {
	for _, lang := range []string{"en", "ko"} {
		raw, err := os.ReadFile("../../../web/messages/" + lang + "/consent.json")
		if err != nil {
			t.Fatal(err)
		}
		var messages struct{ Scope map[string]string }
		if err := json.Unmarshal(raw, &messages); err != nil {
			t.Fatal(err)
		}
		for _, s := range session.MCPScopes() {
			if messages.Scope[strings.ReplaceAll(s, ":", "_")] == "" {
				t.Errorf("web/messages/%s/consent.json has no label for %s", lang, s)
			}
		}
	}
}
