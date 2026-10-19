package postgres

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	scramMinIterations = 4096
	scramMaxIterations = 1_000_000
	scramNonceBytes    = 18
)

type scramClient struct {
	password    []byte
	username    string
	clientNonce string

	clientFirstBare         string
	serverFirst             string
	clientAndServerNonce    string
	salt                    []byte
	iterations              int
	saltedPassword          []byte
	authMessage             []byte
	expectedServerSignature string
}

func newScramClient(password string) (*scramClient, error) {
	random := make([]byte, scramNonceBytes)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	return newScramClientWithNonceAndUser(password, base64.RawStdEncoding.EncodeToString(random), ""), nil
}

func newScramClientWithNonceAndUser(password, nonce, username string) *scramClient {
	return &scramClient{
		// PostgreSQL service-account passwords are expected to be ASCII / already normalized. Use raw UTF-8
		// bytes rather than adding an x/text SASLprep dependency.
		password:    []byte(password),
		username:    username,
		clientNonce: nonce,
	}
}

func (sc *scramClient) clientFirstMessage() []byte {
	sc.clientFirstBare = fmt.Sprintf("n=%s,r=%s", sc.username, sc.clientNonce)
	return []byte("n,," + sc.clientFirstBare)
}

func (sc *scramClient) recvServerFirstMessage(message []byte) error {
	sc.serverFirst = string(append([]byte(nil), message...))
	attrs := make(map[byte]string)
	for _, attribute := range strings.Split(sc.serverFirst, ",") {
		if len(attribute) < 3 || attribute[1] != '=' {
			return errors.New("invalid SCRAM server-first attribute")
		}
		key := attribute[0]
		if _, duplicate := attrs[key]; duplicate {
			return fmt.Errorf("duplicate SCRAM server-first attribute %c=", key)
		}
		attrs[key] = attribute[2:]
	}
	if _, ok := attrs['m']; ok {
		return errors.New("SCRAM server-first has an unsupported mandatory extension (m=)")
	}

	combinedNonce, ok := attrs['r']
	if !ok {
		return errors.New("SCRAM server-first missing r=")
	}
	if !strings.HasPrefix(combinedNonce, sc.clientNonce) || len(combinedNonce) <= len(sc.clientNonce) {
		return errors.New("SCRAM server nonce does not strictly extend client nonce")
	}

	saltText, ok := attrs['s']
	if !ok {
		return errors.New("SCRAM server-first missing s=")
	}
	salt, err := base64.StdEncoding.DecodeString(saltText)
	if err != nil {
		return fmt.Errorf("invalid SCRAM salt: %w", err)
	}

	iterationText, ok := attrs['i']
	if !ok {
		return errors.New("SCRAM server-first missing i=")
	}
	iterations, err := strconv.Atoi(iterationText)
	if err != nil {
		return fmt.Errorf("invalid SCRAM iteration count: %w", err)
	}
	if iterations < scramMinIterations || iterations > scramMaxIterations {
		return fmt.Errorf("SCRAM iteration count %d out of allowed range [%d, %d]", iterations, scramMinIterations, scramMaxIterations)
	}

	sc.clientAndServerNonce = combinedNonce
	sc.salt = salt
	sc.iterations = iterations
	return nil
}

func (sc *scramClient) clientFinalMessage() ([]byte, error) {
	if sc.serverFirst == "" || sc.clientAndServerNonce == "" {
		return nil, errors.New("SCRAM server-first message was not received")
	}
	clientFinalWithoutProof := "c=biws,r=" + sc.clientAndServerNonce
	sc.saltedPassword = pbkdf2.Key(sc.password, sc.salt, sc.iterations, sha256.Size, sha256.New)
	sc.authMessage = []byte(strings.Join([]string{sc.clientFirstBare, sc.serverFirst, clientFinalWithoutProof}, ","))

	clientKey := computeHMAC(sc.saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	clientSignature := computeHMAC(storedKey[:], sc.authMessage)
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSignature[i]
	}

	serverKey := computeHMAC(sc.saltedPassword, []byte("Server Key"))
	serverSignature := computeHMAC(serverKey, sc.authMessage)
	sc.expectedServerSignature = base64.StdEncoding.EncodeToString(serverSignature)
	return []byte(clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof)), nil
}

func (sc *scramClient) verifyServerFinal(message []byte) error {
	expected := []byte("v=" + sc.expectedServerSignature)
	if sc.expectedServerSignature == "" || !hmac.Equal(message, expected) {
		return errors.New("SCRAM server signature mismatch")
	}
	return nil
}

func computeHMAC(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	return mac.Sum(nil)
}
