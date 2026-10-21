package main

import (
	"github.com/ridi-oss/proxy-monster/goproxy/athena"
	"github.com/ridi-oss/proxy-monster/goproxy/mysql"
	"github.com/ridi-oss/proxy-monster/goproxy/postgres"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

var registry = spi.MustRegistry(athena.Provider{}, mysql.Provider{}, postgres.Provider{})
