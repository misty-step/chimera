// Command chimera is the single Chimera binary. All behavior lives in internal/cli.
package main

import (
	"os"

	"github.com/misty-step/chimera/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], cli.OSEnv(), os.Stdout, os.Stderr))
}
