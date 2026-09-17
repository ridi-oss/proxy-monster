// Package providers is pmon's composition root: the engines it knows and what each one provides.
package providers

import (
	"github.com/ridi-oss/proxy-monster/pmon/driver"
	"github.com/ridi-oss/proxy-monster/pmon/providers/mysql"
	"github.com/ridi-oss/proxy-monster/pmon/providers/postgres"
)

var builtins = driver.NewRegistry(
	mysql.Provider{},
	postgres.Provider{},
)

func Builtins() *driver.Registry { return builtins }
