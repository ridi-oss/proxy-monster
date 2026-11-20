package main

import (
	"log/slog"
	"os"

	"github.com/ridi-oss/proxy-monster/goproxy/edge"
)

func main() {
	if err := edge.Run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
