package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// prodHoldYAML hits the policy gateway's critical rule (step id contains
// "deploy" + env marks production), so a triggered run is held at
// pending_approval under the default autonomy level L2 (P7⑧).
const prodHoldYAML = `
version: 1
pipeline:
  name: polapi
  concurrency: 1
  env:
    environment: production
  steps:
    - id: build
      image: alpine
      commands:
        - echo build
    - id: deploy-prod
      image: alpine
      needs: [build]
      commands:
        - echo deploy
`

// heldRunID creates the prod-hold pipeline, triggers a run, and waits until it
// is held at pending_approval.
func heldRunID(t *testing.T, c *http.Client, base string) int64 {
	t.Helper()
	createPipeline(t, c, base, "polapi", prodHoldYAML)
	id := triggerRun(t, c, base, "polapi")
	if s := waitForRunStatus(t, c, base, id, "pending_approval"); s != "pending_approval" {
		t.Fatalf("run %d status = %q, want pending_approval", id, s)
	}
	return id
}

// TestRejectReasonAPI (P7⑧): a {"reason"} body on POST /api/runs/{id}/reject
// is persisted on the run and echoed back in the run JSON; a reason-less
// reject omits the field; double-reject is a 409; a malformed body is a 400.
func TestRejectReasonAPI(t *testing.T) {
	ts, _ := newTestServer(t)
	c := ts.Client()
	base := ts.URL

	// Reject with a reason: 200 + reason persisted + echoed in run JSON.
	id := heldRunID(t, c, base)
	code, out := doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/reject", base, id),
		map[string]any{"reason": "flaky tests on CI"})
	if code != http.StatusOK {
		t.Fatalf("reject: got %d, want 200 (body=%v)", code, out)
	}
	code, out = doJSON(t, c, "GET", fmt.Sprintf("%s/api/runs/%d", base, id), nil)
	if code != http.StatusOK {
		t.Fatalf("get run: got %d", code)
	}
	rn, _ := out["run"].(map[string]any)
	if rn["status"] != "rejected" {
		t.Fatalf("status = %v, want rejected", rn["status"])
	}
	if rn["reject_reason"] != "flaky tests on CI" {
		t.Fatalf("reject_reason = %v, want the posted reason", rn["reject_reason"])
	}

	// Reason-less reject: reject_reason must be omitted (omitempty).
	id2 := heldRunID(t, c, base)
	if code, out := doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/reject", base, id2), nil); code != http.StatusOK {
		t.Fatalf("reject without body: got %d, want 200 (body=%v)", code, out)
	}
	code, out = doJSON(t, c, "GET", fmt.Sprintf("%s/api/runs/%d", base, id2), nil)
	rn2, _ := out["run"].(map[string]any)
	if v, present := rn2["reject_reason"]; present {
		t.Fatalf("reason-less reject must omit reject_reason, got %q", v)
	}

	// Rejecting a run that is no longer pending_approval is a 409.
	if code, _ := doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/reject", base, id),
		map[string]any{"reason": "again"}); code != http.StatusConflict {
		t.Fatalf("double reject: got %d, want 409", code)
	}

	// A malformed JSON body is a 400.
	id3 := heldRunID(t, c, base)
	resp, err := c.Post(fmt.Sprintf("%s/api/runs/%d/reject", base, id3),
		"application/json", strings.NewReader("{not json"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid body: got %d, want 400", resp.StatusCode)
	}
}
