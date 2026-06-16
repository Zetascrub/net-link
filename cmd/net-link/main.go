package main

import (
	"os"

	"github.com/Zetascrub/net-link/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
