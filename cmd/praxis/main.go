package main

import (
	"os"

	"praxis/internal/app/localdaemon"
	"praxis/internal/transport/cli"
)

var version = "1.3.8"

func main() {
	os.Exit(cli.Execute(version, localdaemon.Hooks(version)))
}
