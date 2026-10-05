// Package providers is pmon's composition root: the registry of every engine it can format connection strings for or broker.
package providers

import (
	"github.com/ridi-oss/proxy-monster/pmon/driver"
	"github.com/ridi-oss/proxy-monster/pmon/internal/providers/athena"
	"github.com/ridi-oss/proxy-monster/pmon/internal/providers/mysql"
	"github.com/ridi-oss/proxy-monster/pmon/internal/providers/postgres"
)

var builtins = driver.NewRegistry(
	mysql.Provider{},
	postgres.Provider{},
	athena.Provider{},
)

// Builtins is the immutable registry the daemon and the formatting API consult.
func Builtins() *driver.Registry { return builtins }
