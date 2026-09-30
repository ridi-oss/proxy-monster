// Package targettls builds the client-side TLS config the proxy uses on its own connection to the target DB.
package targettls

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Mode is how the proxy secures its connection to the target DB.
type Mode string

const (
	Disable    Mode = "disable"
	Require    Mode = "require"
	VerifyCA   Mode = "verify-ca"
	VerifyFull Mode = "verify-full"
)

// rdsBundle is https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem.
//
//go:embed rds-global-bundle.pem
var rdsBundle []byte

// ParseMode maps a PM_TARGET_TLS value to a Mode; blank is Disable.
func ParseMode(raw string) (Mode, error) {
	switch mode := Mode(strings.ToLower(strings.TrimSpace(raw))); mode {
	case "":
		return Disable, nil
	case Disable, Require, VerifyCA, VerifyFull:
		return mode, nil
	default:
		return "", fmt.Errorf("PM_TARGET_TLS=%q must be one of disable, require, verify-ca, verify-full", raw)
	}
}

// DefaultCAs is the verify-full trust when PM_TARGET_CA is unset.
const DefaultCAs = "system,rds"

// Config returns nil for Disable. Require encrypts without verifying the server but still sends SNI. VerifyFull
// checks the chain against cas and the certificate against host. VerifyCA checks only the chain, so cas must be
// files naming a CA that signs nothing but this target (a Cloud SQL per-instance CA).
func Config(mode Mode, cas, host string) (*tls.Config, error) {
	if strings.TrimSpace(cas) != "" && mode != VerifyFull && mode != VerifyCA {
		return nil, fmt.Errorf("PM_TARGET_CA is only read with PM_TARGET_TLS=verify-ca or verify-full (got %s)", mode)
	}
	switch mode {
	case Disable:
		return nil, nil
	case Require:
		return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, ServerName: host}, nil
	case VerifyCA:
		if strings.TrimSpace(cas) == "" {
			return nil, fmt.Errorf("PM_TARGET_TLS=verify-ca needs PM_TARGET_CA: the CA is the only identity check")
		}
		for _, source := range strings.Split(cas, ",") {
			if source := strings.TrimSpace(source); source == "system" || source == "rds" {
				return nil, fmt.Errorf("PM_TARGET_TLS=verify-ca cannot trust %q: its CAs sign other servers too", source)
			}
		}
		roots, err := rootPool(cas)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: host,
			// Go has no chain-only mode: skip its check, which includes the hostname, and verify the chain here.
			InsecureSkipVerify: true,
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 {
					return errors.New("target DB presented no certificate")
				}
				intermediates := x509.NewCertPool()
				for _, cert := range state.PeerCertificates[1:] {
					intermediates.AddCert(cert)
				}
				_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates})
				return err
			},
		}, nil
	case VerifyFull:
		if strings.TrimSpace(host) == "" {
			return nil, fmt.Errorf("PM_TARGET_TLS=verify-full needs PM_TARGET_HOST to check the certificate against")
		}
		if strings.TrimSpace(cas) == "" {
			cas = DefaultCAs
		}
		roots, err := rootPool(cas)
		if err != nil {
			return nil, err
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: host}, nil
	default:
		return nil, fmt.Errorf("unknown target TLS mode %q", mode)
	}
}

// rootPool reads a comma-separated list of CA sources: "system" (the OS trust store), "rds" (the embedded RDS
// global bundle), or a path to a PEM file.
func rootPool(cas string) (*x509.CertPool, error) {
	sources := strings.Split(cas, ",")
	roots := x509.NewCertPool()
	for i, source := range sources {
		sources[i] = strings.TrimSpace(source)
		if sources[i] == "system" {
			system, err := x509.SystemCertPool()
			if err != nil {
				return nil, fmt.Errorf("PM_TARGET_CA: loading the system trust store: %w", err)
			}
			roots = system
		}
	}
	for _, source := range sources {
		switch source {
		case "":
			return nil, fmt.Errorf("PM_TARGET_CA=%q has an empty entry", cas)
		case "system":
		case "rds":
			if !roots.AppendCertsFromPEM(rdsBundle) {
				return nil, errors.New("PM_TARGET_CA: the embedded RDS bundle holds no certificate")
			}
		default:
			pem, err := os.ReadFile(source)
			if err != nil {
				return nil, fmt.Errorf("PM_TARGET_CA: %w", err)
			}
			if !roots.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("PM_TARGET_CA: %s holds no PEM certificate", source)
			}
		}
	}
	return roots, nil
}
