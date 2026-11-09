package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/ridi-oss/proxy-monster/goproxy/boot"
	"github.com/ridi-oss/proxy-monster/goproxy/edge"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

func main() {
	if err := run(registry, os.Getenv("PM_MODE")); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run(registry spi.Registry, mode string) error {
	switch strings.TrimSpace(mode) {
	case "":
		return boot.Run(registry)
	case "edge":
		return edge.Run()
	default:
		return fmt.Errorf("PM_MODE=%q is not a known mode (want edge, or unset for a datasource proxy)", mode)
	}
}
