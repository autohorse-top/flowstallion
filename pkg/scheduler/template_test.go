package scheduler

import (
	"testing"
	"time"

	"github.com/flowstallion/flowstallion/pkg/store"
)

// TestExpandImageTemplate: table-driven unit test for the docker_build tag
// template expansion ({{sha}} / {{branch}} / {{ts}}).
func TestExpandImageTemplate(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 30, 0, 0, time.UTC)
	cases := []struct {
		name string
		tpl  string
		run  store.Run
		want string
	}{
		{"sha", "flowstallion-local/app:{{sha}}", store.Run{SHA: "abc123"}, "flowstallion-local/app:abc123"},
		{"branch from source_ref", "flowstallion-local/app:{{branch}}", store.Run{SourceRef: "main"}, "flowstallion-local/app:main"},
		{"PR head wins over source_ref", "flowstallion-local/app:{{branch}}",
			store.Run{SourceRef: "main", HeadRef: "hotfix-x"}, "flowstallion-local/app:hotfix-x"},
		{"branch sanitized", "flowstallion-local/app:{{branch}}",
			store.Run{SourceRef: "release/1.0"}, "flowstallion-local/app:release-1.0"},
		{"sha unknown fallback", "flowstallion-local/app:{{sha}}", store.Run{}, "flowstallion-local/app:unknown"},
		{"branch unknown fallback", "flowstallion-local/app:{{branch}}", store.Run{}, "flowstallion-local/app:unknown"},
		{"ts compact format", "flowstallion-local/app:{{ts}}", store.Run{}, "flowstallion-local/app:20261026123000"},
		{"no placeholders untouched", "flowstallion-local/app:v1", store.Run{SHA: "abc123"}, "flowstallion-local/app:v1"},
		{"all three", "flowstallion-local/app:{{sha}}-{{branch}}-{{ts}}",
			store.Run{SHA: "abc123", SourceRef: "main"}, "flowstallion-local/app:abc123-main-20261026123000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := expandImageTemplate(tc.tpl, tc.run, now); got != tc.want {
				t.Errorf("expandImageTemplate = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSchedulerExpandsDockerBuildImage: end-to-end through the scheduler —
// a docker_build step's image template is expanded with the run's trigger
// metadata before the executor sees it.
func TestSchedulerExpandsDockerBuildImage(t *testing.T) {
	const yaml = `
version: 1
pipeline:
  name: tmpl
  steps:
    - id: build
      type: docker_build
      image: flowstallion-local/app:{{sha}}-{{branch}}
      push: true
      timeout: 30
`
	ts := newTestScheduler(t)
	ts.upsert("tmpl", yaml)

	id, err := ts.s.TriggerWithMeta("tmpl", "push", "main", store.RunMeta{SHA: "abc123def"})
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	run := ts.waitForTerminal(id)
	if run.Status != store.RunSuccess {
		t.Fatalf("status = %q, want success", run.Status)
	}
	if got := ts.fx.imageFor("build"); got != "flowstallion-local/app:abc123def-main" {
		t.Fatalf("expanded image = %q, want flowstallion-local/app:abc123def-main", got)
	}
}

// TestSchedulerDockerBuildUnknownSHA: manual trigger carries no SHA and no
// branch — placeholders fall back to "unknown" rather than empty tags.
func TestSchedulerDockerBuildUnknownSHA(t *testing.T) {
	const yaml = `
version: 1
pipeline:
  name: tmpl2
  steps:
    - id: build
      type: docker_build
      image: flowstallion-local/app:{{sha}}
      timeout: 30
`
	ts := newTestScheduler(t)
	ts.upsert("tmpl2", yaml)

	id, err := ts.s.Trigger("tmpl2", "manual", "")
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	run := ts.waitForTerminal(id)
	if run.Status != store.RunSuccess {
		t.Fatalf("status = %q, want success", run.Status)
	}
	if got := ts.fx.imageFor("build"); got != "flowstallion-local/app:unknown" {
		t.Fatalf("expanded image = %q, want flowstallion-local/app:unknown", got)
	}
}
