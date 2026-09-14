package providers

import (
	"github.com/ridi-oss/proxy-monster/pmon/driver"
	"github.com/ridi-oss/proxy-monster/pmon/providers/athena"
	"github.com/ridi-oss/proxy-monster/pmon/providers/mysql"
	"github.com/ridi-oss/proxy-monster/pmon/providers/postgres"
)

var builtins = driver.NewRegistry(
	driver.Provider{
		Engine: "mysql", Renderer: mysql.Provider{}, Broker: mysql.Provider{},
		SupportedFormats: []driver.Format{driver.URL, driver.JDBC, driver.GoDSN, driver.CLI}, DefaultFormat: driver.URL,
	},
	driver.Provider{
		Engine: "postgres", Renderer: postgres.Renderer{},
		SupportedFormats: []driver.Format{driver.URL, driver.JDBC, driver.GoDSN, driver.CLI}, DefaultFormat: driver.URL,
		UnavailableReason: "postgres brokering not yet supported",
	},
	driver.Provider{
		Engine: "athena", Renderer: athena.Provider{}, Broker: athena.Provider{},
		SupportedFormats: []driver.Format{driver.CLI, driver.URL, driver.JDBC, "python", "node", "aws-config"}, DefaultFormat: driver.CLI,
	},
)

func Builtins() *driver.Registry { return builtins }
