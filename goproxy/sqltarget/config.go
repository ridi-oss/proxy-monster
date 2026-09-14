package sqltarget

import "strconv"

type Config struct {
	Host     string
	Port     int
	Db       string
	User     string
	Password string
}

func Configure(lookup func(string) (string, bool), defaultPort int) Config {
	value := func(name, fallback string) string {
		if value, ok := lookup(name); ok {
			return value
		}
		return fallback
	}
	port, err := strconv.ParseInt(value("PM_TARGET_PORT", ""), 10, 32)
	if err != nil || port == 0 {
		port = int64(defaultPort)
	}
	return Config{
		Host:     value("PM_TARGET_HOST", "localhost"),
		Port:     int(port),
		Db:       value("PM_TARGET_DB", "acme"),
		User:     value("PM_TARGET_USER", "acme"),
		Password: value("PM_TARGET_PASSWORD", "acme"),
	}
}
