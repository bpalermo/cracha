// Command cracha-webhook is the mutating admission webhook that injects the CSI volume and the AWS SDK environment into enabled pods (docs/design.md, section 7.4).
//
// Nothing is implemented yet; the binary reports its version and exits.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/bpalermo/cracha/common/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("cracha-webhook %s\n", version.Version)
		return
	}
	fmt.Fprintln(os.Stderr, "cracha-webhook: not implemented")
	os.Exit(1)
}
