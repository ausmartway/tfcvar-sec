package version

import (
	"bytes"
	"fmt"
)

// Variables set at build time
var (
	Version        = "0.2.1"
	PackageManager = "goreleaser"
)

// GetVersion - Get the version of the binary
// defaults to "progname v0 | via unknown"
func GetVersion(progname string) *Info {
	return &Info{
		ProgName:       progname,
		Version:        Version,
		PackageManager: PackageManager,
	}
}

func (c *Info) String() string {
	if c.ProgName == "" {
		c.ProgName = "progname"
	}
	var versionString bytes.Buffer
	fmt.Fprintf(&versionString, "%s %s | via %s", c.ProgName, c.Version, c.PackageManager)
	return versionString.String()
}
