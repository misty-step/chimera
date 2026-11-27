package cli

import "fmt"

var (
	flagTarget = flagSpec{Long: "target", Arg: "ref", Help: "ref changes land on (default: land.target)"}
	flagSquash = flagSpec{Long: "squash", Help: "land each change as one commit carrying the trailer union"}
	flagOnce   = flagSpec{Long: "once", Help: "process at most one queued change"}
)

func runLandEnqueue(c *ctx) error { return fmt.Errorf("not implemented") }
func runLandStatus(c *ctx) error  { return fmt.Errorf("not implemented") }
func runLandRun(c *ctx) error     { return fmt.Errorf("not implemented") }
