// Command cracha-broker issues AWS credentials to workloads: it verifies a pod's JWT-SVID, consults the authorization store and assumes a shape role on the workload's behalf (docs/design.md, section 6).
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
		fmt.Printf("cracha-broker %s\n", version.Version)
		return
	}
	fmt.Fprintln(os.Stderr, "cracha-broker: not implemented")
	os.Exit(1)
}
