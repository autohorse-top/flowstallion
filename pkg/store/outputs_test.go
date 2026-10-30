// P7④: run sha column and step outputs round-trip tests.
package store

import (
	"path/filepath"
	"testing"
)

func TestRunSHARoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "sha.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	pid, err := s.UpsertPipeline("shademo", "version: 1\npipeline:\n  name: shademo\n  steps:\n    - id: a\n      image: alpine\n      commands: [echo a]\n")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	meta := RunMeta{SHA: "abc123def", HeadRef: "main"}
	id, err := s.CreateRunMeta(pid, "push", "main", meta)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	r, err := s.GetRun(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if r.SHA != "abc123def" {
		t.Errorf("SHA = %q, want abc123def", r.SHA)
	}

	// A plain CreateRun (no metadata) must round-trip SHA = "".
	id2, err := s.CreateRun(pid, "manual", "")
	if err != nil {
		t.Fatalf("create plain: %v", err)
	}
	r2, err := s.GetRun(id2)
	if err != nil {
		t.Fatalf("get plain: %v", err)
	}
	if r2.SHA != "" {
		t.Errorf("plain SHA = %q, want empty", r2.SHA)
	}

	runs, err := s.ListRuns(pid, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for i := range runs {
		if runs[i].ID == id && runs[i].SHA != "abc123def" {
			t.Errorf("ListRuns SHA = %q, want abc123def", runs[i].SHA)
		}
	}
}

func TestSetRunStepOutputs(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "out.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	pid, err := s.UpsertPipeline("outdemo", "version: 1\npipeline:\n  name: outdemo\n  steps:\n    - id: build\n      image: alpine\n      commands: [echo a]\n")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	rid, err := s.CreateRun(pid, "manual", "")
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	if _, err := s.AddRunStep(rid, "build", 0, "alpine", `["echo a"]`); err != nil {
		t.Fatalf("add step: %v", err)
	}

	raw := `{"image_ref":"reg.io/app:1"}`
	if err := s.SetRunStepOutputs(rid, "build", raw); err != nil {
		t.Fatalf("set outputs: %v", err)
	}
	steps, err := s.ListRunSteps(rid)
	if err != nil {
		t.Fatalf("list steps: %v", err)
	}
	if len(steps) != 1 || steps[0].Outputs != raw {
		t.Fatalf("outputs = %+v, want %s", steps, raw)
	}

	// Unknown step id must error (no silent no-op).
	if err := s.SetRunStepOutputs(rid, "nope", raw); err == nil {
		t.Error("set outputs on unknown step: want error, got nil")
	}

	// A step without outputs reads back as "".
	if _, err := s.AddRunStep(rid, "b", 1, "alpine", `["echo b"]`); err != nil {
		t.Fatalf("add step2: %v", err)
	}
	steps, err = s.ListRunSteps(rid)
	if err != nil {
		t.Fatalf("list steps 2: %v", err)
	}
	for _, st := range steps {
		if st.StepID == "b" && st.Outputs != "" {
			t.Errorf("step b outputs = %q, want empty", st.Outputs)
		}
	}
}
