package cli

import "fmt"

var flagCheck = flagSpec{Long: "check", Help: "print the forge check summary; exit 1 on FAIL, 3 on PENDING"}

func runTrail(c *ctx) error { return fmt.Errorf("not implemented") }
