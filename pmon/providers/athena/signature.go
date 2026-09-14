package athena

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const signingAlgorithm = "AWS4-HMAC-SHA256"

var errSignature = errors.New("pmon.athena.invalidSignature")

func localCredentials(principal, datasource, password string) aws.Credentials {
	identity := "pmon/athena/v1\x00" + strconv.Itoa(len(principal)) + ":" + principal + datasource
	id := sha256.Sum256([]byte(identity))
	secret := hmac.New(sha256.New, []byte(password))
	_, _ = secret.Write([]byte(identity))
	return aws.Credentials{
		AccessKeyID:     "PMON" + strings.ToUpper(hex.EncodeToString(id[:12])),
		SecretAccessKey: hex.EncodeToString(secret.Sum(nil)),
	}
}

type authorization struct {
	credential, headers, signature string
}

func parseAuthorization(value string) (authorization, error) {
	value, ok := strings.CutPrefix(value, signingAlgorithm+" ")
	if !ok {
		return authorization{}, errSignature
	}
	fields := make(map[string]string, 3)
	for _, field := range strings.Split(value, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok || value == "" || fields[key] != "" {
			return authorization{}, errSignature
		}
		fields[key] = value
	}
	if len(fields) != 3 || fields["Credential"] == "" || fields["SignedHeaders"] == "" || fields["Signature"] == "" {
		return authorization{}, errSignature
	}
	return authorization{fields["Credential"], fields["SignedHeaders"], fields["Signature"]}, nil
}

func verifySignature(request *http.Request, body []byte, credentials aws.Credentials, region string, now time.Time) error {
	if len(request.Header.Values("Authorization")) != 1 || len(request.Header.Values("X-Amz-Date")) != 1 ||
		len(request.Header.Values("X-Amz-Target")) != 1 || len(request.Header.Values("Content-Type")) != 1 ||
		len(request.Header.Values("X-Amz-Security-Token")) != 0 {
		return errSignature
	}
	auth, err := parseAuthorization(request.Header.Get("Authorization"))
	if err != nil {
		return err
	}
	stamp, err := time.Parse("20060102T150405Z", request.Header.Get("X-Amz-Date"))
	if err != nil || now.Sub(stamp) > 5*time.Minute || stamp.Sub(now) > 5*time.Minute {
		return errSignature
	}
	if auth.credential != credentials.AccessKeyID+"/"+stamp.Format("20060102")+"/"+region+"/athena/aws4_request" {
		return errSignature
	}
	signature, err := hex.DecodeString(auth.signature)
	if err != nil || len(signature) != sha256.Size {
		return errSignature
	}
	hash := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(hash[:])
	if values := request.Header.Values("X-Amz-Content-Sha256"); len(values) > 1 || (len(values) == 1 && values[0] != payloadHash) {
		return errSignature
	}

	canonical := request.Clone(request.Context())
	canonical.Header = make(http.Header)
	canonical.URL.Scheme = "http"
	canonical.URL.Host = request.Host
	canonical.ContentLength = -1
	signed := make(map[string]bool)
	last := ""
	for _, name := range strings.Split(auth.headers, ";") {
		if name == "" || name != strings.ToLower(name) || name <= last {
			return errSignature
		}
		last = name
		signed[name] = true
		switch name {
		case "host":
			if request.Host == "" {
				return errSignature
			}
		case "content-length":
			if request.ContentLength <= 0 || request.ContentLength != int64(len(body)) {
				return errSignature
			}
			canonical.ContentLength = request.ContentLength
		default:
			values := request.Header.Values(name)
			if len(values) == 0 {
				return errSignature
			}
			canonical.Header[http.CanonicalHeaderKey(name)] = values
		}
	}
	for _, name := range []string{"host", "content-type", "x-amz-date", "x-amz-target"} {
		if !signed[name] {
			return errSignature
		}
	}
	if err := v4.NewSigner().SignHTTP(request.Context(), credentials, canonical, payloadHash, "athena", region, stamp); err != nil {
		return errSignature
	}
	expected, err := parseAuthorization(canonical.Header.Get("Authorization"))
	if err != nil || expected.headers != auth.headers {
		return errSignature
	}
	expectedSignature, err := hex.DecodeString(expected.signature)
	if err != nil || subtle.ConstantTimeCompare(signature, expectedSignature) != 1 {
		return errSignature
	}
	return nil
}
