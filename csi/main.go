// Command cracha-csi is the CSI node plugin that writes a pod's JWT-SVID where the AWS SDK reads it, before the pod's containers start, and keeps it fresh (docs/design.md, section 7).
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
		fmt.Printf("cracha-csi %s\n", version.Version)
		return
	}
	fmt.Fprintln(os.Stderr, "cracha-csi: not implemented")
	os.Exit(1)
}
