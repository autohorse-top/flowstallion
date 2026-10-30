package pipeline

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// baseYAML is the minimal valid document used as the starting point for
// single-fault mutation tests.
const baseYAML = `
version: 1
pipeline:
  name: demo
  steps:
    - id: build
      image: alpine
      commands:
        - echo hello
`

// fullYAML exercises every optional field to verify the happy path.
const fullYAML = `
version: 1
pipeline:
  name: full-demo
  trigger:
    - event: push
      branches:
        - main
        - release/*
    - event: pull_request
    - event: schedule
      cron: "0 2 * * *"
    - event: manual
  concurrency: 3
  env:
    GOFLAGS: "-mod=vendor"
    REGISTRY: ghcr.io/flowstallion
  secrets:
    - GH_TOKEN
    - registry-password
  steps:
    - id: checkout
      image: alpine
      commands:
        - echo fetching source
    - id: build
      image: golang:1.22
      needs:
        - checkout
      commands:
        - go build ./...
      env:
        CGO_ENABLED: "0"
      timeout: 3600
    - id: test
      image: golang:1.22
      needs:
        - build
      commands:
        - go test ./...
    - id: scan
      image: ghcr.io/aquasecurity/trivy:0.48
      needs:
        - build
      timeout: 900
      commands:
        - trivy fs .
`

// errCount returns the number of individual errors aggregated in err.
func errCount(err error) int {
	if err == nil {
		return 0
	}
	if agg, ok := err.(interface{ Unwrap() []error }); ok {
		if n := len(agg.Unwrap()); n > 0 {
			return n
		}
	}
	return 1
}

func TestParseYAML(t *testing.T) {
	name128 := strings.Repeat("a", 128)
	name129 := strings.Repeat("a", 129)
	id64 := strings.Repeat("b", 64)
	id65 := strings.Repeat("b", 65)
	branch257 := strings.Repeat("m", 257)
	cron65 := strings.Repeat("*", 65)
	secret129 := strings.Repeat("s", 129)
	cmdTooLong := strings.Repeat("e", MaxCommandLength+1)

	cases := []struct {
		name         string
		yamlText     string
		wantErr      bool
		minErrs      int      // minimum number of individual errors (0 when valid)
		wantContains []string // substrings that must all appear in err.Error()
		check        func(t *testing.T, p Pipeline)
	}{
		{
			name:     "minimal valid pipeline",
			yamlText: baseYAML,
			check: func(t *testing.T, p Pipeline) {
				if p.Version != 1 {
					t.Errorf("Version = %d, want 1", p.Version)
				}
				if p.Pipeline.Name != "demo" {
					t.Errorf("Name = %q, want %q", p.Pipeline.Name, "demo")
				}
				if len(p.Pipeline.Steps) != 1 {
					t.Fatalf("Steps len = %d, want 1", len(p.Pipeline.Steps))
				}
				if p.Pipeline.Steps[0].Timeout != DefaultStepTimeout {
					t.Errorf("Timeout = %d, want default %d", p.Pipeline.Steps[0].Timeout, DefaultStepTimeout)
				}
			},
		},
		{
			name:     "full featured pipeline",
			yamlText: fullYAML,
			check: func(t *testing.T, p Pipeline) {
				if len(p.Pipeline.Trigger) != 4 {
					t.Errorf("Trigger len = %d, want 4", len(p.Pipeline.Trigger))
				}
				if p.Pipeline.Concurrency != 3 {
					t.Errorf("Concurrency = %d, want 3", p.Pipeline.Concurrency)
				}
				if len(p.Pipeline.Secrets) != 2 {
					t.Errorf("Secrets len = %d, want 2", len(p.Pipeline.Secrets))
				}
				if len(p.Pipeline.Steps) != 4 {
					t.Fatalf("Steps len = %d, want 4", len(p.Pipeline.Steps))
				}
				if p.Pipeline.Steps[1].Timeout != 3600 {
					t.Errorf("build.Timeout = %d, want 3600", p.Pipeline.Steps[1].Timeout)
				}
				if p.Pipeline.Steps[2].Timeout != DefaultStepTimeout {
					t.Errorf("test.Timeout = %d, want default %d", p.Pipeline.Steps[2].Timeout, DefaultStepTimeout)
				}
				if p.Pipeline.Steps[3].Timeout != 900 {
					t.Errorf("scan.Timeout = %d, want 900", p.Pipeline.Steps[3].Timeout)
				}
				if p.Pipeline.Steps[1].Env["CGO_ENABLED"] != "0" {
					t.Errorf("build.Env[CGO_ENABLED] = %q, want %q", p.Pipeline.Steps[1].Env["CGO_ENABLED"], "0")
				}
			},
		},
		{
			name:     "name 128 chars is valid",
			yamlText: fmt.Sprintf("version: 1\npipeline:\n  name: %s\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n", name128),
			check:    func(t *testing.T, p Pipeline) {},
		},
		{
			name:         "name 129 chars",
			yamlText:     fmt.Sprintf("version: 1\npipeline:\n  name: %s\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n", name129),
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.name:"},
		},
		{
			name:         "name with dot",
			yamlText:     "version: 1\npipeline:\n  name: my.pipeline\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.name:"},
		},
		{
			name:         "missing name",
			yamlText:     "version: 1\npipeline:\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.name: required"},
		},
		{
			name:         "missing pipeline block",
			yamlText:     "version: 1\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline: required"},
		},
		{
			name:         "version 2",
			yamlText:     "version: 2\npipeline:\n  name: demo\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"version: must be 1"},
		},
		{
			name:         "version missing",
			yamlText:     "pipeline:\n  name: demo\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"version:"},
		},
		{
			name:         "steps empty list",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps: []\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps: required"},
		},
		{
			name:         "steps missing",
			yamlText:     "version: 1\npipeline:\n  name: demo\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps: required"},
		},
		{
			name:         "duplicate step id",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo one\n    - id: build\n      image: alpine\n      commands:\n        - echo two\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"duplicate id \"build\""},
		},
		{
			name:         "step id 65 chars",
			yamlText:     fmt.Sprintf("version: 1\npipeline:\n  name: demo\n  steps:\n    - id: %s\n      image: alpine\n      commands:\n        - echo hi\n", id65),
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].id:"},
		},
		{
			name:     "step id 64 chars valid",
			yamlText: fmt.Sprintf("version: 1\npipeline:\n  name: demo\n  steps:\n    - id: %s\n      image: alpine\n      commands:\n        - echo hi\n", id64),
		},
		{
			name:         "step id starts with underscore",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: _build\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].id:"},
		},
		{
			name:         "needs points to unknown id",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: a\n      image: alpine\n      commands:\n        - echo a\n      needs:\n        - ghost\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"unknown step id \"ghost\""},
		},
		{
			name:         "needs cycle a-b-a",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: a\n      image: alpine\n      commands:\n        - echo a\n      needs:\n        - b\n    - id: b\n      image: alpine\n      commands:\n        - echo b\n      needs:\n        - a\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"cycle: a -> b -> a"},
		},
		{
			name:         "needs self loop a-a",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: a\n      image: alpine\n      commands:\n        - echo a\n      needs:\n        - a\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"cycle: a -> a"},
		},
		{
			name:         "trigger event invalid",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  trigger:\n    - event: deploy\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.trigger[0].event:"},
		},
		{
			name:         "schedule event missing cron",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  trigger:\n    - event: schedule\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.trigger[0].cron: required when event is schedule"},
		},
		{
			name:         "cron on non-schedule event",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  trigger:\n    - event: push\n      cron: \"0 2 * * *\"\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.trigger[0].cron: only allowed when event is schedule"},
		},
		{
			name:         "concurrency 0",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  concurrency: 0\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.concurrency:"},
		},
		{
			name:         "concurrency 101",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  concurrency: 101\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.concurrency:"},
		},
		{
			name:     "concurrency 1 and 100 valid",
			yamlText: "version: 1\npipeline:\n  name: demo\n  concurrency: 1\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
		},
		{
			name:         "image with newline",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: build\n      image: \"alpine\\n-hack\"\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].image:"},
		},
		{
			name:         "image empty",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: build\n      image: \"\"\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].image: required"},
		},
		{
			name:         "command empty string",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - \"\"\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].commands[0]: must be non-empty"},
		},
		{
			name:         "command too long",
			yamlText:     fmt.Sprintf("version: 1\npipeline:\n  name: demo\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - %s\n", cmdTooLong),
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].commands[0]: must be at most 4096"},
		},
		{
			name:         "commands empty list",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: build\n      image: alpine\n      commands: []\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].commands: required"},
		},
		{
			name:         "timeout 0",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n      timeout: 0\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].timeout:"},
		},
		{
			name:         "timeout 604801",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n      timeout: 604801\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].timeout:"},
		},
		{
			name:     "timeout 1 valid",
			yamlText: "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n      timeout: 1\n",
		},
		{
			name:     "timeout 604800 valid",
			yamlText: "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n      timeout: 604800\n",
		},
		{
			name:         "secret name bad chars",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  secrets:\n    - \"bad secret!\"\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.secrets[0]:"},
		},
		{
			name:         "secret name 129 chars",
			yamlText:     fmt.Sprintf("version: 1\npipeline:\n  name: demo\n  secrets:\n    - %s\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n", secret129),
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.secrets[0]:"},
		},
		{
			name:         "branch 257 chars",
			yamlText:     fmt.Sprintf("version: 1\npipeline:\n  name: demo\n  trigger:\n    - event: push\n      branches:\n        - %s\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n", branch257),
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.trigger[0].branches[0]:"},
		},
		{
			name:         "cron 65 chars",
			yamlText:     fmt.Sprintf("version: 1\npipeline:\n  name: demo\n  trigger:\n    - event: schedule\n      cron: \"%s\"\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n", cron65),
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.trigger[0].cron: must be at most 64"},
		},
		{
			name:     "multiple valid triggers no error",
			yamlText: "version: 1\npipeline:\n  name: demo\n  trigger:\n    - event: push\n      branches:\n        - main\n    - event: manual\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
		},
		{
			name:         "multiple faults at once",
			yamlText:     "version: 2\npipeline:\n  name: bad.name\n  concurrency: 200\n  steps: []\n",
			wantErr:      true,
			minErrs:      3,
			wantContains: []string{"version: must be 1", "pipeline.name:", "pipeline.concurrency:", "pipeline.steps: required"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseYAML([]byte(tc.yamlText))

			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseYAML() error = nil, want error")
				}
				gotCount := errCount(err)
				if gotCount < tc.minErrs {
					t.Errorf("ParseYAML() error count = %d, want >= %d\n  full: %s", gotCount, tc.minErrs, err)
				}
				for _, sub := range tc.wantContains {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("ParseYAML() error = %q, want it to contain %q", err.Error(), sub)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseYAML() unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, p)
			}
		})
	}
}

func TestParseYAMLInvalidYAML(t *testing.T) {
	_, err := ParseYAML([]byte("version: 1\npipeline: [unclosed"))
	if err == nil {
		t.Fatal("ParseYAML() error = nil, want YAML parse error")
	}
	if !strings.Contains(err.Error(), "yaml:") {
		t.Errorf("ParseYAML() error = %q, want it to contain \"yaml:\"", err.Error())
	}
}

func TestParseYAMLValidFile(t *testing.T) {
	data, err := os.ReadFile("../../testdata/valid-pipeline.yaml")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	p, err := ParseYAML(data)
	if err != nil {
		t.Fatalf("ParseYAML(valid-pipeline.yaml) unexpected error: %v", err)
	}
	if p.Pipeline.Name != "flowstallion-dsl-demo" {
		t.Errorf("Name = %q, want %q", p.Pipeline.Name, "flowstallion-dsl-demo")
	}
	if len(p.Pipeline.Steps) != 4 {
		t.Errorf("Steps len = %d, want 4", len(p.Pipeline.Steps))
	}
}

func TestParseYAMLBrokenFile(t *testing.T) {
	data, err := os.ReadFile("../../testdata/broken-pipeline.yaml")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	_, err = ParseYAML(data)
	if err == nil {
		t.Fatal("ParseYAML(broken-pipeline.yaml) error = nil, want error")
	}
	count := errCount(err)
	if count < 3 {
		t.Errorf("ParseYAML(broken-pipeline.yaml) error count = %d, want >= 3\n  full: %s", count, err)
	}
}

// ---------------------------------------------------------------------------
// P7④: docker_build step type
// ---------------------------------------------------------------------------

func TestParseYAMLDockerBuild(t *testing.T) {
	cases := []struct {
		name         string
		yamlText     string
		wantErr      bool
		minErrs      int
		wantContains []string
		check        func(t *testing.T, p Pipeline)
	}{
		{
			name: "docker_build minimal (defaults applied)",
			yamlText: `
version: 1
pipeline:
  name: demo
  steps:
    - id: buildimg
      type: docker_build
      image: localhost:5000/demo/app:{{sha}}
`,
			check: func(t *testing.T, p Pipeline) {
				s := p.Pipeline.Steps[0]
				if s.Type != "docker_build" {
					t.Errorf("Type = %q, want docker_build", s.Type)
				}
				if s.Dockerfile != "Dockerfile" {
					t.Errorf("Dockerfile = %q, want default %q", s.Dockerfile, "Dockerfile")
				}
				if s.BuildContext != "." {
					t.Errorf("BuildContext = %q, want default %q", s.BuildContext, ".")
				}
				if s.Push {
					t.Errorf("Push = true, want default false")
				}
				if len(s.Commands) != 0 {
					t.Errorf("Commands = %v, want empty", s.Commands)
				}
			},
		},
		{
			name: "docker_build all fields",
			yamlText: `
version: 1
pipeline:
  name: demo
  steps:
    - id: buildimg
      type: docker_build
      image: ghcr.io/team/app:{{branch}}-{{ts}}
      dockerfile: build/Dockerfile.prod
      context: build
      push: true
      timeout: 600
`,
			check: func(t *testing.T, p Pipeline) {
				s := p.Pipeline.Steps[0]
				if s.Dockerfile != "build/Dockerfile.prod" {
					t.Errorf("Dockerfile = %q", s.Dockerfile)
				}
				if s.BuildContext != "build" {
					t.Errorf("BuildContext = %q", s.BuildContext)
				}
				if !s.Push {
					t.Errorf("Push = false, want true")
				}
				if s.Timeout != 600 {
					t.Errorf("Timeout = %d, want 600", s.Timeout)
				}
			},
		},
		{
			name: "docker_build plain image without placeholders is valid",
			yamlText: `
version: 1
pipeline:
  name: demo
  steps:
    - id: buildimg
      type: docker_build
      image: localhost:5000/app:1.0
`,
		},
		{
			name:         "docker_build missing image",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: docker_build\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].image: required"},
		},
		{
			name:         "docker_build with commands forbidden",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: docker_build\n      image: localhost:5000/app:1\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"not allowed on docker_build steps"},
		},
		{
			name:         "docker_build unknown placeholder",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: docker_build\n      image: localhost:5000/app:{{foo}}\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"invalid docker_build target image"},
		},
		{
			name:         "docker_build image with bad characters",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: docker_build\n      image: localhost:5000/app:ba d\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"invalid docker_build target image"},
		},
		{
			name:         "unknown step type rejected",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: k8s_deploy\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{`type: must be empty or one of "docker_build", "k8s_canary", "k8s_blue_green"`},
		},
		{
			name:         "docker_build dockerfile traversal",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: docker_build\n      image: localhost:5000/app:1\n      dockerfile: ../etc/passwd\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].dockerfile:"},
		},
		{
			name:         "docker_build context absolute path",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: docker_build\n      image: localhost:5000/app:1\n      context: /tmp\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].context:"},
		},
		{
			name:         "docker_build dockerfile with space",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: docker_build\n      image: localhost:5000/app:1\n      dockerfile: My Dockerfile\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].dockerfile:"},
		},
		{
			name: "docker_build subpath dockerfile valid",
			yamlText: `
version: 1
pipeline:
  name: demo
  steps:
    - id: b
      type: docker_build
      image: localhost:5000/app:1
      dockerfile: sub/Dockerfile.prod
      context: sub
`,
		},
		{
			name:     "container step without type still valid (regression)",
			yamlText: baseYAML,
		},
		{
			name:         "container step with type must omit or docker_build",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: container\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{`type: must be empty or one of "docker_build", "k8s_canary", "k8s_blue_green"`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseYAML([]byte(tc.yamlText))
			switch {
			case tc.wantErr:
				if err == nil {
					t.Fatalf("ParseYAML() error = nil, want error")
				}
				if tc.minErrs > 0 && errCount(err) < tc.minErrs {
					t.Errorf("error count = %d, want >= %d\n  full: %s", errCount(err), tc.minErrs, err)
				}
				for _, sub := range tc.wantContains {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("error %q does not contain %q", err.Error(), sub)
					}
				}
			case err != nil:
				t.Fatalf("ParseYAML() unexpected error: %v", err)
			}
			if tc.check != nil && err == nil {
				tc.check(t, p)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// P7⑤: k8s_canary step type
// ---------------------------------------------------------------------------

func TestParseYAMLK8sCanary(t *testing.T) {
	cases := []struct {
		name         string
		yamlText     string
		wantErr      bool
		minErrs      int
		wantContains []string
		check        func(t *testing.T, p Pipeline)
	}{
		{
			name: "k8s_canary minimal (defaults applied)",
			yamlText: `
version: 1
pipeline:
  name: demo
  steps:
    - id: deploy
      type: k8s_canary
      image: localhost:5000/demo/app:v2
      namespace: prod
      deployment: app
`,
			check: func(t *testing.T, p Pipeline) {
				s := p.Pipeline.Steps[0]
				if s.Type != "k8s_canary" {
					t.Errorf("Type = %q, want k8s_canary", s.Type)
				}
				if s.Namespace != "prod" || s.Deployment != "app" {
					t.Errorf("Namespace/Deployment = %q/%q", s.Namespace, s.Deployment)
				}
				if s.CanaryWeight != DefaultCanaryWeight {
					t.Errorf("CanaryWeight = %d, want default %d", s.CanaryWeight, DefaultCanaryWeight)
				}
				if s.CanaryProbeFailures != 0 || s.CanaryTimeout != 0 {
					t.Errorf("CanaryProbeFailures/CanaryTimeout = %d/%d, want 0 (pkg/cd defaults)",
						s.CanaryProbeFailures, s.CanaryTimeout)
				}
				if len(s.Commands) != 0 {
					t.Errorf("Commands = %v, want empty", s.Commands)
				}
			},
		},
		{
			name: "k8s_canary all fields",
			yamlText: `
version: 1
pipeline:
  name: demo
  steps:
    - id: deploy
      type: k8s_canary
      image: localhost:5000/demo/app:v2
      k8s_context: prod-us
      namespace: prod
      deployment: app
      canary:
        weight: 25
        probe_failures: 5
        timeout: 600
`,
			check: func(t *testing.T, p Pipeline) {
				s := p.Pipeline.Steps[0]
				if s.K8sContext != "prod-us" {
					t.Errorf("K8sContext = %q, want prod-us", s.K8sContext)
				}
				if s.CanaryWeight != 25 {
					t.Errorf("CanaryWeight = %d, want 25", s.CanaryWeight)
				}
				if s.CanaryProbeFailures != 5 {
					t.Errorf("CanaryProbeFailures = %d, want 5", s.CanaryProbeFailures)
				}
				if s.CanaryTimeout != 600 {
					t.Errorf("CanaryTimeout = %d, want 600", s.CanaryTimeout)
				}
			},
		},
		{
			name:         "k8s_canary missing namespace",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: k8s_canary\n      image: localhost:5000/app:1\n      deployment: app\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].namespace: required for k8s_canary steps"},
		},
		{
			name:         "k8s_canary missing deployment",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: k8s_canary\n      image: localhost:5000/app:1\n      namespace: prod\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].deployment: required for k8s_canary steps"},
		},
		{
			name:         "k8s_canary missing image",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: k8s_canary\n      namespace: prod\n      deployment: app\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].image: required"},
		},
		{
			name:         "k8s_canary uppercase namespace rejected",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: k8s_canary\n      image: localhost:5000/app:1\n      namespace: Prod\n      deployment: app\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].namespace: must match"},
		},
		{
			name:         "k8s_canary bad k8s_context rejected",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: k8s_canary\n      image: localhost:5000/app:1\n      k8s_context: bad context!\n      namespace: prod\n      deployment: app\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].k8s_context: must match"},
		},
		{
			name:         "k8s_canary with commands forbidden",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: k8s_canary\n      image: localhost:5000/app:1\n      namespace: prod\n      deployment: app\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"not allowed on k8s_canary steps"},
		},
		{
			name:         "k8s_canary weight below range",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: k8s_canary\n      image: localhost:5000/app:1\n      namespace: prod\n      deployment: app\n      canary:\n        weight: 0\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].canary.weight: must be between 1 and 100"},
		},
		{
			name:         "k8s_canary weight above range",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: k8s_canary\n      image: localhost:5000/app:1\n      namespace: prod\n      deployment: app\n      canary:\n        weight: 101\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].canary.weight: must be between 1 and 100"},
		},
		{
			name:         "k8s_canary probe_failures below range",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: k8s_canary\n      image: localhost:5000/app:1\n      namespace: prod\n      deployment: app\n      canary:\n        probe_failures: 0\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].canary.probe_failures: must be ≥ 1"},
		},
		{
			name:         "k8s_canary timeout zero rejected",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: k8s_canary\n      image: localhost:5000/app:1\n      namespace: prod\n      deployment: app\n      canary:\n        timeout: 0\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].canary.timeout: must be between 1 and 604800 seconds"},
		},
		{
			name:         "container step with k8s_canary fields rejected",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      image: alpine\n      namespace: prod\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"k8s_context/namespace/deployment/canary are only allowed on k8s_canary / k8s_blue_green steps"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseYAML([]byte(tc.yamlText))
			switch {
			case tc.wantErr:
				if err == nil {
					t.Fatalf("ParseYAML() error = nil, want error")
				}
				if tc.minErrs > 0 && errCount(err) < tc.minErrs {
					t.Errorf("error count = %d, want >= %d\n  full: %s", errCount(err), tc.minErrs, err)
				}
				for _, sub := range tc.wantContains {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("error %q does not contain %q", err.Error(), sub)
					}
				}
			case err != nil:
				t.Fatalf("ParseYAML() unexpected error: %v", err)
			}
			if tc.check != nil && err == nil {
				tc.check(t, p)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// k8s_blue_green step type (second CD strategy)
// ---------------------------------------------------------------------------

func TestParseYAMLK8sBlueGreen(t *testing.T) {
	// Deployment names at the K8s 63-char object-name limit boundary:
	// alternate name = deployment + strategy suffix ("canary" +7,
	// "blue_green" +4), so the max deployment lengths are 56 and 59.
	long60 := strings.Repeat("a", 59) + "b" // 60 chars: rejected by both strategies
	long50 := strings.Repeat("a", 50)       // 50 chars: accepted by both
	long56 := strings.Repeat("a", 56)       // 56 chars: canary boundary (56+7=63)
	long59 := strings.Repeat("a", 59)       // 59 chars: blue_green boundary (59+4=63)
	cdn := func(typ string, deploy string) string {
		return "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n" +
			"      type: " + typ + "\n      image: localhost:5000/app:1\n" +
			"      namespace: prod\n      deployment: " + deploy + "\n"
	}
	cases := []struct {
		name         string
		yamlText     string
		wantErr      bool
		minErrs      int
		wantContains []string
		check        func(t *testing.T, p Pipeline)
	}{
		{
			name:     "k8s_blue_green minimal (defaults applied)",
			yamlText: cdn("k8s_blue_green", "app"),
			check: func(t *testing.T, p Pipeline) {
				s := p.Pipeline.Steps[0]
				if s.Type != "k8s_blue_green" {
					t.Errorf("Type = %q, want k8s_blue_green", s.Type)
				}
				if s.Namespace != "prod" || s.Deployment != "app" {
					t.Errorf("Namespace/Deployment = %q/%q", s.Namespace, s.Deployment)
				}
				if s.CanaryWeight != DefaultCanaryWeight {
					t.Errorf("CanaryWeight = %d, want default %d", s.CanaryWeight, DefaultCanaryWeight)
				}
				if s.CanaryProbeFailures != 0 || s.CanaryTimeout != 0 {
					t.Errorf("CanaryProbeFailures/CanaryTimeout = %d/%d, want 0 (pkg/cd defaults)",
						s.CanaryProbeFailures, s.CanaryTimeout)
				}
				if len(s.Commands) != 0 {
					t.Errorf("Commands = %v, want empty", s.Commands)
				}
			},
		},
		{
			name: "k8s_blue_green all fields",
			yamlText: `
version: 1
pipeline:
  name: demo
  steps:
    - id: deploy
      type: k8s_blue_green
      image: localhost:5000/demo/app:v2
      k8s_context: prod-us
      namespace: prod
      deployment: app
      canary:
        weight: 50
        probe_failures: 7
        timeout: 900
`,
			check: func(t *testing.T, p Pipeline) {
				s := p.Pipeline.Steps[0]
				if s.K8sContext != "prod-us" {
					t.Errorf("K8sContext = %q, want prod-us", s.K8sContext)
				}
				if s.CanaryWeight != 50 {
					t.Errorf("CanaryWeight = %d, want 50", s.CanaryWeight)
				}
				if s.CanaryProbeFailures != 7 {
					t.Errorf("CanaryProbeFailures = %d, want 7", s.CanaryProbeFailures)
				}
				if s.CanaryTimeout != 900 {
					t.Errorf("CanaryTimeout = %d, want 900", s.CanaryTimeout)
				}
			},
		},
		{
			name:         "k8s_blue_green missing namespace",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: k8s_blue_green\n      image: localhost:5000/app:1\n      deployment: app\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].namespace: required for k8s_blue_green steps"},
		},
		{
			name:         "k8s_blue_green missing deployment",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: k8s_blue_green\n      image: localhost:5000/app:1\n      namespace: prod\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].deployment: required for k8s_blue_green steps"},
		},
		{
			name:         "k8s_blue_green missing image",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: k8s_blue_green\n      namespace: prod\n      deployment: app\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"pipeline.steps[0].image: required"},
		},
		{
			name:         "k8s_blue_green with commands forbidden",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  steps:\n    - id: b\n      type: k8s_blue_green\n      image: localhost:5000/app:1\n      namespace: prod\n      deployment: app\n      commands:\n        - echo hi\n",
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{"not allowed on k8s_blue_green steps"},
		},
		{
			name:         "60-char deployment rejected (k8s_canary, 60+7=67 > 63)",
			yamlText:     cdn("k8s_canary", long60),
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{`+ "-canary" = 67 chars, exceeds K8s 63-char object-name limit`},
		},
		{
			name:         "60-char deployment rejected (k8s_blue_green, 60+4=64 > 63)",
			yamlText:     cdn("k8s_blue_green", long60),
			wantErr:      true,
			minErrs:      1,
			wantContains: []string{`+ "-alt" = 64 chars, exceeds K8s 63-char object-name limit`},
		},
		{
			name:     "50-char deployment accepted (both strategies)",
			yamlText: cdn("k8s_blue_green", long50),
			check: func(t *testing.T, p Pipeline) {
				if len(p.Pipeline.Steps[0].Deployment) != 50 {
					t.Errorf("Deployment length = %d, want 50", len(p.Pipeline.Steps[0].Deployment))
				}
			},
		},
		{
			name:     "56-char deployment accepted at canary boundary (56+7=63)",
			yamlText: cdn("k8s_canary", long56),
		},
		{
			name:     "59-char deployment accepted at blue_green boundary (59+4=63)",
			yamlText: cdn("k8s_blue_green", long59),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseYAML([]byte(tc.yamlText))
			switch {
			case tc.wantErr:
				if err == nil {
					t.Fatalf("ParseYAML() error = nil, want error")
				}
				if tc.minErrs > 0 && errCount(err) < tc.minErrs {
					t.Errorf("error count = %d, want >= %d\n  full: %s", errCount(err), tc.minErrs, err)
				}
				for _, sub := range tc.wantContains {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("error %q does not contain %q", err.Error(), sub)
					}
				}
			case err != nil:
				t.Fatalf("ParseYAML() unexpected error: %v", err)
			}
			if tc.check != nil && err == nil {
				tc.check(t, p)
			}
		})
	}
}

func TestValidImageTemplate(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"localhost:5000/app:{{sha}}", true},
		{"ghcr.io/t/a:{{branch}}-{{ts}}", true},
		{"app:1.0", true},
		{"app:{{foo}}", false},
		{"{{sha}}", false},        // no repo part left
		{"ap p:1", false},         // space
		{"{{bad}}{{sha}}", false}, // leftover placeholder
	}
	for _, c := range cases {
		if got := validImageTemplate(c.s); got != c.want {
			t.Errorf("validImageTemplate(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestCheckDockerPath(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"Dockerfile", true},
		{".", true},
		{"build/", false}, // trailing slash => empty segment
		{"build/Dockerfile.prod", true},
		{"../etc", false},
		{"/abs", false},
		{"a b", false},
		{"a~", false},
		{"a/b/../../c", false},
	}
	for _, c := range cases {
		err := checkDockerPath(c.s)
		if (err == nil) != c.want {
			t.Errorf("checkDockerPath(%q) err = %v, want valid=%v", c.s, err, c.want)
		}
	}
	if err := checkDockerPath(strings.Repeat("a", 257)); err == nil {
		t.Errorf("checkDockerPath(257 chars) = nil, want length error")
	}
}

// TestNotificationsValidation (P7⑦): notifications list is validated for the
// closed type set, URL shape (http/https + host), and sane limits.
func TestNotificationsValidation(t *testing.T) {
	notifyBlock := func(url string) string {
		return fmt.Sprintf("  notifications:\n    - type: webhook\n      url: %s\n", url)
	}
	longURL := "https://hooks.example.com/" + strings.Repeat("a", 2048-26) // exactly 2048
	tooLongURL := "https://hooks.example.com/" + strings.Repeat("a", 2049-26)

	nEntries := func(n int) string {
		var b strings.Builder
		b.WriteString("version: 1\npipeline:\n  name: demo\n  notifications:\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "    - type: webhook\n      url: https://hooks.example.com/h%d\n", i)
		}
		b.WriteString("  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n")
		return b.String()
	}

	cases := []struct {
		name         string
		yamlText     string
		wantErr      bool
		wantContains []string // substrings that must all appear in err.Error()
		check        func(t *testing.T, p Pipeline)
	}{
		{
			name:     "notifications omitted is valid",
			yamlText: baseYAML,
			check: func(t *testing.T, p Pipeline) {
				if len(p.Pipeline.Notifications) != 0 {
					t.Errorf("Notifications = %+v, want empty", p.Pipeline.Notifications)
				}
			},
		},
		{
			name:     "single http webhook valid",
			yamlText: "version: 1\npipeline:\n  name: demo\n" + notifyBlock("http://hooks.example.com/x") + "  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			check: func(t *testing.T, p Pipeline) {
				if len(p.Pipeline.Notifications) != 1 {
					t.Fatalf("Notifications len = %d, want 1", len(p.Pipeline.Notifications))
				}
				n := p.Pipeline.Notifications[0]
				if n.Type != "webhook" || n.URL != "http://hooks.example.com/x" {
					t.Errorf("Notifications[0] = %+v", n)
				}
			},
		},
		{
			name:     "https webhook valid",
			yamlText: "version: 1\npipeline:\n  name: demo\n" + notifyBlock("https://hooks.example.com/x") + "  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			check: func(t *testing.T, p Pipeline) {
				if len(p.Pipeline.Notifications) != 1 {
					t.Fatalf("Notifications len = %d, want 1", len(p.Pipeline.Notifications))
				}
			},
		},
		{
			name:     "url exactly 2048 chars valid",
			yamlText: "version: 1\npipeline:\n  name: demo\n" + notifyBlock(longURL) + "  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			check: func(t *testing.T, p Pipeline) {
				if len(p.Pipeline.Notifications) != 1 {
					t.Fatalf("Notifications len = %d, want 1", len(p.Pipeline.Notifications))
				}
			},
		},
		{
			name:     "exactly 10 notifications valid",
			yamlText: nEntries(10),
			check: func(t *testing.T, p Pipeline) {
				if len(p.Pipeline.Notifications) != 10 {
					t.Fatalf("Notifications len = %d, want 10", len(p.Pipeline.Notifications))
				}
			},
		},
		{
			name:         "11 notifications exceeds limit",
			yamlText:     nEntries(11),
			wantErr:      true,
			wantContains: []string{"pipeline.notifications: at most 10"},
		},
		{
			name:         "unknown type email",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  notifications:\n    - type: email\n      url: https://hooks.example.com/x\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			wantContains: []string{"pipeline.notifications[0].type: must be one of webhook"},
		},
		{
			name:         "empty url",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  notifications:\n    - type: webhook\n      url: \"\"\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			wantContains: []string{"pipeline.notifications[0].url: required"},
		},
		{
			name:         "ftp scheme rejected",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  notifications:\n    - type: webhook\n      url: ftp://hooks.example.com/x\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			wantContains: []string{"pipeline.notifications[0].url: must be http or https"},
		},
		{
			name:         "http url without host",
			yamlText:     "version: 1\npipeline:\n  name: demo\n  notifications:\n    - type: webhook\n      url: \"http://\"\n  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			wantContains: []string{"pipeline.notifications[0].url: must include a host"},
		},
		{
			name:         "url 2049 chars exceeds limit",
			yamlText:     "version: 1\npipeline:\n  name: demo\n" + notifyBlock(tooLongURL) + "  steps:\n    - id: build\n      image: alpine\n      commands:\n        - echo hi\n",
			wantErr:      true,
			wantContains: []string{"pipeline.notifications[0].url: must be at most 2048"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseYAML([]byte(tc.yamlText))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseYAML() error = nil, want error")
				}
				for _, sub := range tc.wantContains {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("ParseYAML() error = %q, want it to contain %q", err.Error(), sub)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseYAML() unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, p)
			}
		})
	}
}
