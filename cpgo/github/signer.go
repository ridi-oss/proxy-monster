package github

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/golang-jwt/jwt/v4"
)

// Signer signs the App's JWTs.
type Signer = ghinstallation.Signer

// NewPEMSigner reads a PKCS#1 (`BEGIN RSA PRIVATE KEY`, GitHub's download) or PKCS#8 PEM.
func NewPEMSigner(pemText string) (Signer, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(strings.ReplaceAll(pemText, `\n`, "\n")))
	if err != nil {
		return nil, errors.New("invalid GitHub App private key")
	}
	return ghinstallation.NewRSASigner(jwt.SigningMethodRS256, key), nil
}

type kmsAPI interface {
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
}

type kmsSigner struct {
	keyID string
	kms   kmsAPI
}

// NewKMSSigner signs with an RSA KMS key holding the App's private key, so the key never leaves KMS.
func NewKMSSigner(ctx context.Context, keyID string) (Signer, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("github: AWS config: %w", err)
	}
	return kmsSigner{keyID: keyID, kms: kms.NewFromConfig(cfg)}, nil
}

func (s kmsSigner) Sign(claims jwt.Claims) (string, error) {
	input, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SigningString()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(input))
	out, err := s.kms.Sign(context.Background(), &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest[:],
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return "", fmt.Errorf("github: KMS sign: %w", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(out.Signature), nil
}
