package sqldb

import (
	"crypto/tls"
	"strconv"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	"github.com/ridi-oss/proxy-monster/goproxy/targettls"
)

// Flags is the kong grammar MySQL and PostgreSQL share: the target DB and the service account the proxy
// signs in with. Port is a string so a blank or non-numeric value falls back to the engine default.
type Flags struct {
	Host     string `env:"PM_TARGET_HOST" default:"localhost"`
	Port     string `env:"PM_TARGET_PORT"`
	Db       string `env:"PM_TARGET_DB" default:"acme"`
	User     string `env:"PM_TARGET_USER" default:"acme"`
	Password string `env:"PM_TARGET_PASSWORD" default:"acme"`
	TLS      string `env:"PM_TARGET_TLS"`
	CA       string `env:"PM_TARGET_CA"`
}

// Settings is how the proxy reaches its target DB and signs in as the service account.
type Settings struct {
	Host     string
	Port     int
	Db       string
	User     string
	Password string
	// TLS secures the proxy's own connection to the target DB; nil is plaintext.
	TLS *tls.Config
}

// NewSettings normalizes flags for engine e, whose default target port replaces a missing one.
func NewSettings(flags Flags, e *engines.Engine) (Settings, error) {
	// 32-bit so a value like 4294967297 falls back to the default instead of registering a truncated port.
	port, err := strconv.ParseInt(flags.Port, 10, 32)
	if err != nil || port == 0 {
		port = int64(e.DefaultTargetPort)
	}
	mode, err := targettls.ParseMode(flags.TLS)
	if err != nil {
		return Settings{}, err
	}
	tlsConfig, err := targettls.Config(mode, flags.CA, flags.Host)
	if err != nil {
		return Settings{}, err
	}
	return Settings{Host: flags.Host, Port: int(port), Db: flags.Db, User: flags.User, Password: flags.Password, TLS: tlsConfig}, nil
}
