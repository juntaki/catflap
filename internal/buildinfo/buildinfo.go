// Package buildinfo holds the version string stamped at release build
// time (via -ldflags "-X"), so the CLI and the MCP server report the
// same version instead of two independently drifting literals.
package buildinfo

var Version = "dev"
