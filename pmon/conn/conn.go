// Package conn renders local connection strings with the principal and sticky loopback password.
package conn

import (
	"slices"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
	"github.com/ridi-oss/proxy-monster/pmon/providers"
)

type Format = driver.Format

const (
	URL   = driver.URL
	JDBC  = driver.JDBC
	GoDSN = driver.GoDSN
	CLI   = driver.CLI
	Host  = driver.Host
)

type Target = driver.Target

type Options = driver.Options

func SupportedFormats(engine string) []Format {
	provider, ok := providers.Builtins().Lookup(engine)
	if !ok || provider.Renderer == nil {
		return nil
	}
	return provider.SupportedFormats
}

func DefaultFormat(engine string) Format {
	provider, ok := providers.Builtins().Lookup(engine)
	if !ok || provider.Renderer == nil {
		return ""
	}
	return provider.DefaultFormat
}

func SupportsFormat(engine string, format Format) bool {
	return slices.Contains(SupportedFormats(engine), format)
}

func String(format Format, target Target) string {
	return StringWithOptions(format, target, Options{})
}

func StringWithOptions(format Format, target Target, options Options) string {
	provider, ok := providers.Builtins().Lookup(target.Engine)
	if !ok || provider.Renderer == nil {
		// The public rendering API defaults unknown engines to MySQL, independently of broker support.
		provider, _ = providers.Builtins().Lookup("mysql")
	}
	target.ConnectionInfo = target.ConnectionInfo.Clone()
	return provider.Renderer.Render(format, target, options)
}
