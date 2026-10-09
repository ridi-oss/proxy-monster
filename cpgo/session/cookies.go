package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SetSigned writes a by-value cookie the way Ktor signs one: "<json>/<hex HMAC-SHA256 of the json>",
// URI-encoded, lasting maxAge seconds.
func (r *Resolver) SetSigned(w http.ResponseWriter, name string, value any, maxAge int64) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	signed := string(payload) + "/" + r.sign(string(payload))
	encoded := strings.ReplaceAll(url.QueryEscape(signed), "+", "%20")
	expires := time.Now().Add(time.Duration(maxAge) * time.Second)
	r.setCookie(w, name, encoded, fmt.Sprintf("Max-Age=%d; Expires=%s", maxAge, httpDate(expires)))
	return nil
}

// ReadSigned decodes a signed by-value cookie into out, reporting false when it is absent, forged, or carries
// a field out lacks, so one signed cookie cannot stand in for another.
func (r *Resolver) ReadSigned(req *http.Request, name string, out any) bool {
	c, err := req.Cookie(name)
	if err != nil {
		return false
	}
	raw, err := url.QueryUnescape(c.Value)
	if err != nil {
		return false
	}
	i := strings.LastIndexByte(raw, '/')
	if i < 0 || !hmac.Equal([]byte(r.sign(raw[:i])), []byte(raw[i+1:])) {
		return false
	}
	dec := json.NewDecoder(strings.NewReader(raw[:i]))
	dec.DisallowUnknownFields()
	return dec.Decode(out) == nil
}

// Clear expires a cookie the request carried; like Ktor's sessions.clear, an absent one is left alone.
func (r *Resolver) Clear(w http.ResponseWriter, req *http.Request, name string) {
	if _, err := req.Cookie(name); err == nil {
		r.setCookie(w, name, "", "Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
	}
}

func (r *Resolver) sign(payload string) string {
	mac := hmac.New(sha256.New, []byte(r.settings.Secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
