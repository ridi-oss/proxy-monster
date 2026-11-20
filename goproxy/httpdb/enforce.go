package httpdb

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

var ErrResultShape = errors.New("httpdb: result shape cannot be enforced")

// SubmittedQuery is the text and parameters the proxy sends: the control plane's rewrite, which has the
// parameters bound into it, else the client's own.
func SubmittedQuery(sql string, parameters []string, decision *spi.Decision) (string, []string) {
	if decision != nil && decision.RewrittenSQL != nil {
		return *decision.RewrittenSQL, nil
	}
	return sql, parameters
}

// CheckWidth fails a result whose column count differs from the width its context was admitted under.
func CheckWidth(expected *int32, width int) error {
	if expected != nil && (int(*expected) != width || *expected < 0) {
		return ErrResultShape
	}
	return nil
}

// ColumnDigest fingerprints column metadata regardless of layout; a mismatch with a non-empty bound is ErrResultShape.
func ColumnDigest(columns json.RawMessage, bound []byte) ([]byte, error) {
	var shape any
	decoder := json.NewDecoder(bytes.NewReader(columns))
	decoder.UseNumber()
	if err := decoder.Decode(&shape); err != nil {
		return nil, ErrResultShape
	}
	canonical, err := json.Marshal(shape)
	if err != nil {
		return nil, ErrResultShape
	}
	digest := sha256.Sum256(canonical)
	if len(bound) != 0 && !bytes.Equal(bound, digest[:]) {
		return nil, ErrResultShape
	}
	return digest[:], nil
}

// RedactDiagnostics replaces the string value of every key in keys, at any depth: a target echoes stored
// values through status and error messages, which masking never sees.
func RedactDiagnostics(body []byte, keys []string) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, ErrResultShape
	}
	redactValue(document, keys)
	redacted, err := json.Marshal(document)
	if err != nil {
		return nil, ErrResultShape
	}
	return redacted, nil
}

func redactValue(value any, keys []string) {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			if slices.Contains(keys, key) {
				if _, text := child.(string); text {
					node[key] = relay.RedactedDiagnosticMessage
				}
				continue
			}
			redactValue(child, keys)
		}
	case []any:
		for _, child := range node {
			redactValue(child, keys)
		}
	}
}

// requestBinding fingerprints the upstream submission's fields so a stable-token retry can be matched to the
// context it was admitted under; field order and whitespace do not change the submission.
func requestBinding(body []byte) []byte {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var fields map[string]any
	canonical := body
	if decoder.Decode(&fields) == nil {
		if encoded, err := json.Marshal(fields); err == nil {
			canonical = encoded
		}
	}
	hash := sha256.Sum256(canonical)
	return hash[:]
}

// namespacedToken maps a client idempotency token to one stable upstream token per (datasource, principal),
// so one principal's retry can never return another principal's execution.
func namespacedToken(datasource, principal, token string) string {
	hash := sha256.Sum256([]byte(datasource + "\x00" + principal + "\x00" + token))
	return hex.EncodeToString(hash[:])
}
