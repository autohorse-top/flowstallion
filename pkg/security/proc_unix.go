//go:build darwin || linux

package security

import (
	"os/exec"
	"syscall"
	"time"
)

// groupKill makes the command run in its own process group and kills the
// whole group when the command context is canceled (timeout or external
// cancel). Killing only the direct process is not enough: scanner
// children that inherit the output pipes would keep cmd.Run() blocked.
func groupKill(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
}
