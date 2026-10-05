// Package conn formats a brokered datasource's local connection string through the registered provider. The
// host is always loopback and the credentials are the principal plus the sticky local password: cosmetic to
// the broker, which injects the wire token upstream, but they make a copy-paste string a real client accepts.
package conn

import (
	"slices"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
	"github.com/ridi-oss/proxy-monster/pmon/internal/providers"
)

func SupportedFormats(engine string) []driver.Format {
	provider, ok := providers.Builtins().Lookup(engine)
	if !ok {
		return nil
	}
	return slices.Clone(provider.SupportedFormats())
}

func DefaultFormat(engine string) driver.Format {
	provider, ok := providers.Builtins().Lookup(engine)
	if !ok {
		return ""
	}
	return provider.DefaultFormat()
}

func SupportsFormat(engine string, format driver.Format) bool {
	return slices.Contains(SupportedFormats(engine), format)
}

func String(format driver.Format, target driver.Target) string {
	return StringWithOptions(format, target, driver.Options{})
}

func StringWithOptions(format driver.Format, target driver.Target, options driver.Options) string {
	provider, ok := providers.Builtins().Lookup(target.Engine)
	if !ok {
		// An unknown engine formats as MySQL; callers relied on that before engines were registered.
		provider, _ = providers.Builtins().Lookup("mysql")
	}
	target.ConnectionInfo = target.ConnectionInfo.Clone()
	return provider.FormatConnectionString(format, target, options)
}
