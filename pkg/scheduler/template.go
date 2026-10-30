package scheduler

import (
	"regexp"
	"strings"
	"time"

	"github.com/flowstallion/flowstallion/pkg/store"
)

// imageTagSafe replaces characters that are not legal in a docker tag
// (branch names may carry "/", "+", ...) with "-".
var imageTagSafe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// expandImageTemplate substitutes the docker_build tag placeholders
// ({{sha}}, {{branch}}, {{ts}}) using the run's trigger metadata.
//
//   - {{sha}}    -> run.SHA, or "unknown" when the trigger carries no SHA
//     (manual / schedule runs).
//   - {{branch}} -> PR head ref when present, else the run's source ref
//     (the pushed branch; "" for manual), sanitised to tag-safe
//     characters; "unknown" when empty.
//   - {{ts}}     -> UTC compact timestamp "YYYYMMDDHHMMSS" taken at step
//     start (tag-safe).
func expandImageTemplate(tpl string, run store.Run, now time.Time) string {
	sha := run.SHA
	if sha == "" {
		sha = "unknown"
	}
	branch := run.SourceRef
	if run.HeadRef != "" {
		branch = run.HeadRef
	}
	branch = imageTagSafe.ReplaceAllString(branch, "-")
	if branch == "" {
		branch = "unknown"
	}
	ts := now.Format("20060102150405")

	out := strings.ReplaceAll(tpl, "{{sha}}", sha)
	out = strings.ReplaceAll(out, "{{branch}}", branch)
	out = strings.ReplaceAll(out, "{{ts}}", ts)
	return out
}
