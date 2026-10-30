package scheduler

// P7⑦: webhook notification hooks — trigger matrix on run terminal states
// (success / failed / canceled) and canary rollback.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/flowstallion/flowstallion/pkg/notify"
	"github.com/flowstallion/flowstallion/pkg/store"
)

// ---------------------------------------------------------------------------
// Fakes & fixtures
// ---------------------------------------------------------------------------

type notifyCall struct {
	Urls []string
	Ev   notify.Event
}

// fakeNotifier records every Send call; when fail is set it returns a
// non-nil error for each URL (simulating a dead endpoint).
type fakeNotifier struct {
	mu    sync.Mutex
	calls []notifyCall
	fail  bool
}

func (f *fakeNotifier) Send(ctx context.Context, urls []string, ev notify.Event) []error {
	f.mu.Lock()
	f.calls = append(f.calls, notifyCall{
		Urls: append([]string(nil), urls...),
		Ev:   ev,
	})
	fail := f.fail
	f.mu.Unlock()

	errs := make([]error, len(urls))
	if fail {
		for i := range errs {
			errs[i] = fmt.Errorf("simulated send failure")
		}
	}
	return errs
}

// waitCalls blocks until at least n Send calls have been recorded.
func (f *fakeNotifier) waitCalls(t *testing.T, n int) []notifyCall {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		c := len(f.calls)
		f.mu.Unlock()
		if c >= n {
			f.mu.Lock()
			out := make([]notifyCall, len(f.calls))
			copy(out, f.calls)
			f.mu.Unlock()
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited 5s for %d webhook call(s), got %d", n, c)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// countCalls returns the number of recorded Send calls (for "no call" cases).
func (f *fakeNotifier) countCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

const notifYAML = `
version: 1
pipeline:
  name: notif
  notifications:
    - type: webhook
      url: https://hooks.example.com/one
    - type: webhook
      url: https://hooks.example.com/two
  steps:
    - id: a
      image: alpine
      commands: [echo a]
`

const notifFailYAML = `
version: 1
pipeline:
  name: notiffail
  notifications:
    - type: webhook
      url: https://hooks.example.com/one
  steps:
    - id: a
      image: alpine
      commands: [echo a]
    - id: bad
      image: alpine
      needs: [a]
      commands: [echo bad]
`

const notifSlowYAML = `
version: 1
pipeline:
  name: notifslow
  notifications:
    - type: webhook
      url: https://hooks.example.com/one
  steps:
    - id: a
      image: alpine
      commands: [echo a]
`

const canaryNotifYAML = `
version: 1
pipeline:
  name: p7canarynotif
  notifications:
    - type: webhook
      url: https://hooks.example.com/canary
  steps:
    - id: build
      type: docker_build
      image: registry/demoapp:2.0
    - id: deploy
      type: k8s_canary
      needs: [build]
      image: registry/demoapp:2.0
      k8s_context: e2e
      namespace: default
      deployment: demoapp
      canary:
        weight: 20
`

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestNotifyRunTerminal (P7⑦): each terminal run state fires exactly one
// webhook send with the right payload; no notifications / nil Notifier fire
// nothing; a send failure never changes the run status.
func TestNotifyRunTerminal(t *testing.T) {
	const webBase = "http://console.test"

	cases := []struct {
		name       string
		pipe       string
		yaml       string
		failStep   string
		meta       store.RunMeta
		wantStatus string
		wantPR     int
		wantURLs   int
	}{
		{
			name:       "success run fires once with both urls",
			pipe:       "notif",
			yaml:       notifYAML,
			wantStatus: store.RunSuccess,
			wantPR:     0,
			wantURLs:   2,
		},
		{
			name:       "failed run fires with status failed",
			pipe:       "notiffail",
			yaml:       notifFailYAML,
			failStep:   "bad",
			wantStatus: store.RunFailed,
			wantPR:     0,
			wantURLs:   1,
		},
		{
			name:       "PR run carries PR metadata in payload",
			pipe:       "notif",
			yaml:       notifYAML,
			meta:       store.RunMeta{PR: 42, HeadRef: "feature/login", BaseRef: "main"},
			wantStatus: store.RunSuccess,
			wantPR:     42,
			wantURLs:   2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestScheduler(t)
			ts.upsert(tc.pipe, tc.yaml)
			ts.s.Cfg.WebBaseURL = webBase
			fn := &fakeNotifier{}
			ts.s.Notifier = fn
			if tc.failStep != "" {
				ts.fx.failIDs[tc.failStep] = true
			}

			var runID int64
			var err error
			if tc.meta.PR != 0 {
				runID, err = ts.s.TriggerWithMeta(tc.pipe, "pr", "", tc.meta)
			} else {
				runID, err = ts.s.Trigger(tc.pipe, "manual", "")
			}
			if err != nil {
				t.Fatalf("trigger: %v", err)
			}

			r := ts.waitForTerminal(runID)
			if r.Status != tc.wantStatus {
				t.Fatalf("run status = %q, want %q", r.Status, tc.wantStatus)
			}

			calls := fn.waitCalls(t, 1)
			if len(calls) != 1 {
				t.Fatalf("webhook calls = %d, want exactly 1", len(calls))
			}
			c := calls[0]
			if len(c.Urls) != tc.wantURLs {
				t.Errorf("urls = %v, want %d entry(ies)", c.Urls, tc.wantURLs)
			}
			ev := c.Ev
			if ev.RunID != runID {
				t.Errorf("payload run_id = %d, want %d", ev.RunID, runID)
			}
			if ev.Status != tc.wantStatus {
				t.Errorf("payload status = %q, want %q", ev.Status, tc.wantStatus)
			}
			if ev.PR != tc.wantPR {
				t.Errorf("payload pr = %d, want %d", ev.PR, tc.wantPR)
			}
			if want := webBase + "/run/" + fmt.Sprint(runID); ev.URL != want {
				t.Errorf("payload url = %q, want %q", ev.URL, want)
			}
			if ev.Pipeline != tc.pipe {
				t.Errorf("payload pipeline = %q, want %q", ev.Pipeline, tc.pipe)
			}
			if ev.FinishedAt == "" {
				t.Error("payload finished_at empty, want stamped timestamp")
			}
		})
	}

	t.Run("canceled run fires with status canceled", func(t *testing.T) {
		ts := newTestScheduler(t)
		ts.upsert("notifslow", notifSlowYAML)
		ts.s.Cfg.WebBaseURL = webBase
		fn := &fakeNotifier{}
		ts.s.Notifier = fn
		ts.fx.delay = 300 * time.Millisecond

		runID, err := ts.s.Trigger("notifslow", "manual", "")
		if err != nil {
			t.Fatalf("trigger: %v", err)
		}
		time.Sleep(30 * time.Millisecond) // let step a start
		if err := ts.s.Cancel(runID); err != nil {
			t.Fatalf("cancel: %v", err)
		}
		if r := ts.waitForTerminal(runID); r.Status != store.RunCanceled {
			t.Fatalf("run status = %q, want canceled", r.Status)
		}
		calls := fn.waitCalls(t, 1)
		if len(calls) != 1 {
			t.Fatalf("webhook calls = %d, want exactly 1", len(calls))
		}
		if calls[0].Ev.Status != store.RunCanceled {
			t.Errorf("payload status = %q, want canceled", calls[0].Ev.Status)
		}
		if calls[0].Ev.RunID != runID {
			t.Errorf("payload run_id = %d, want %d", calls[0].Ev.RunID, runID)
		}
	})

	t.Run("pipeline without notifications fires nothing", func(t *testing.T) {
		ts := newTestScheduler(t)
		ts.upsert("linear", linearYAML)
		ts.s.Cfg.WebBaseURL = webBase
		fn := &fakeNotifier{}
		ts.s.Notifier = fn

		runID, err := ts.s.Trigger("linear", "manual", "")
		if err != nil {
			t.Fatalf("trigger: %v", err)
		}
		ts.waitForTerminal(runID)
		time.Sleep(200 * time.Millisecond) // allow the (missing) goroutine to fire
		if n := fn.countCalls(); n != 0 {
			t.Fatalf("webhook calls = %d, want 0", n)
		}
	})

	t.Run("nil notifier fires nothing and does not panic", func(t *testing.T) {
		ts := newTestScheduler(t) // Notifier left nil
		ts.upsert("notif", notifYAML)
		runID, err := ts.s.Trigger("notif", "manual", "")
		if err != nil {
			t.Fatalf("trigger: %v", err)
		}
		if r := ts.waitForTerminal(runID); r.Status != store.RunSuccess {
			t.Fatalf("run status = %q, want success", r.Status)
		}
	})

	t.Run("send failure does not change run status", func(t *testing.T) {
		ts := newTestScheduler(t)
		ts.upsert("notif", notifYAML)
		ts.s.Cfg.WebBaseURL = webBase
		fn := &fakeNotifier{fail: true}
		ts.s.Notifier = fn

		runID, err := ts.s.Trigger("notif", "manual", "")
		if err != nil {
			t.Fatalf("trigger: %v", err)
		}
		if r := ts.waitForTerminal(runID); r.Status != store.RunSuccess {
			t.Fatalf("run status = %q, want success despite webhook failure", r.Status)
		}
		calls := fn.waitCalls(t, 1)
		if len(calls) != 1 {
			t.Fatalf("webhook calls = %d, want 1", len(calls))
		}
	})
}

// TestNotifyCanaryRolledBack (P7⑦): a canary that rolls back fires both the
// run-level "failed" webhook and the canary_rolled_back webhook.
func TestNotifyCanaryRolledBack(t *testing.T) {
	const webBase = "http://console.test"

	ts := newTestScheduler(t)
	ts.upsert("p7canarynotif", canaryNotifYAML)

	fk := newFakeK8s()
	fk.metricsErr = errors.New("scrape boom")
	clk := newFakeClock(10 * time.Second)
	fn := &fakeNotifier{}
	ts.s.CanaryExec = &CanaryExecutor{
		Store: ts.st, Kubectl: fk, Now: clk.Now, Poll: time.Millisecond,
		Notifier: fn, WebBaseURL: webBase,
	}
	ts.s.Notifier = fn
	ts.s.Cfg.WebBaseURL = webBase

	runID, err := ts.s.Trigger("p7canarynotif", "manual", "")
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	r := ts.waitForTerminal(runID)
	if r.Status != store.RunFailed {
		t.Fatalf("run status = %q, want failed (canary rolled back)", r.Status)
	}

	// Two payloads expected: status=failed (run terminal) and
	// status=canary_rolled_back (canary executor).
	calls := fn.waitCalls(t, 2)
	var gotFailed, gotCanary bool
	for _, c := range calls {
		switch c.Ev.Status {
		case store.RunFailed:
			gotFailed = true
		case statusCanaryRolledBack:
			gotCanary = true
		}
	}
	if !gotFailed {
		t.Errorf("no run-level failed payload among %+v", calls)
	}
	if !gotCanary {
		t.Errorf("no canary_rolled_back payload among %+v", calls)
	}
}
