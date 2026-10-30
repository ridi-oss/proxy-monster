package main

import (
	"log/slog"
	"os"

	"github.com/ridi-oss/proxy-monster/goproxy/boot"
	"github.com/ridi-oss/proxy-monster/goproxy/config"
)

func main() {
	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run() error {
	var perEngine engineFlags
	flags, err := config.Parse(&perEngine)
	if err != nil {
		return err
	}
	return boot.Run(flags, perEngine.registry(flags.AdvertiseAddr))
}
