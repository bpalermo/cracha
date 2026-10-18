// Command cracha-agent is the node agent that answers the AWS SDK's credential
// requests from inside every enrolled pod (docs/design.md, section 7).
package main

import (
	"flag"
	"fmt"

	"github.com/bpalermo/cracha/common/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("cracha-agent %s\n", version.Version)
	}
}
