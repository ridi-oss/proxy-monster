package main

import (
	"github.com/ridi-oss/proxy-monster/goproxy/athena"
	"github.com/ridi-oss/proxy-monster/goproxy/mysql"
	"github.com/ridi-oss/proxy-monster/goproxy/postgres"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
)

// engineFlags is every engine's settings, parsed in config's kong pass. MySQL and PostgreSQL read the same
// PM_TARGET_* variables, so they share one sqldb.Flags.
type engineFlags struct {
	SQL    sqldb.Flags  `embed:""`
	Athena athena.Flags `embed:""`
}

func (f engineFlags) registry(advertiseAddr string) spi.Registry {
	return spi.MustRegistry(
		athena.Provider{Flags: f.Athena, AdvertiseAddr: advertiseAddr},
		mysql.Provider{Flags: f.SQL, AdvertiseAddr: advertiseAddr},
		postgres.Provider{Flags: f.SQL, AdvertiseAddr: advertiseAddr},
	)
}
