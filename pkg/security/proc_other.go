//go:build !darwin && !linux

package security

import "os/exec"

// groupKill is a no-op on platforms without process groups.
func groupKill(cmd *exec.Cmd) {}
