package scheduler

import (
	"testing"
	"time"

	"github.com/flowstallion/flowstallion/pkg/store"
)

// TestParseRetention (P7⑧): the FLOWSTALLION_LOG_RETENTION grammar —
// "30d" by-age, "runs=500" keep-last, everything else invalid.
func TestParseRetention(t *testing.T) {
	tests := []struct {
		spec     string
		wantAge  time.Duration
		wantKeep int64
		wantErr  bool
	}{
		{spec: "30d", wantAge: 30 * 24 * time.Hour},
		{spec: "1d", wantAge: 24 * time.Hour},
		{spec: " 30d ", wantAge: 30 * 24 * time.Hour},
		{spec: "runs=500", wantKeep: 500},
		{spec: "runs=1", wantKeep: 1},
		{spec: "", wantErr: true},
		{spec: "0d", wantErr: true},
		{spec: "30", wantErr: true},
		{spec: "d", wantErr: true},
		{spec: "runs=", wantErr: true},
		{spec: "runs=0", wantErr: true},
		{spec: "30h", wantErr: true},
		{spec: "30 days", wantErr: true},
		{spec: "RUNS=5", wantErr: true},
		{spec: "999999d", wantErr: true}, // exceeds the 100-year cap
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			got, err := ParseRetention(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseRetention(%q) = %+v, want error", tt.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRetention(%q): %v", tt.spec, err)
			}
			if got.Age != tt.wantAge || got.Keep != tt.wantKeep {
				t.Fatalf("ParseRetention(%q) = age %v keep %d, want age %v keep %d",
					tt.spec, got.Age, got.Keep, tt.wantAge, tt.wantKeep)
			}
		})
	}
	var zero RetentionPolicy
	if zero.Enabled() {
		t.Fatal("zero RetentionPolicy must be disabled")
	}
}

// TestRetentionTickDisabled (P7⑧): a zero policy is a no-op.
func TestRetentionTickDisabled(t *testing.T) {
	ts := newTestScheduler(t)
	if n, err := ts.s.RetentionTick(); err != nil || n != 0 {
		t.Fatalf("tick = (%d, %v), want (0, nil)", n, err)
	}
}

// TestRetentionTickByAge (P7⑧): with the clock far in the future, logs and
// canary events are purged by the age cutoff; with the clock in the recent
// past, young data survives.
func TestRetentionTickByAge(t *testing.T) {
	ts := newTestScheduler(t)
	pid, err := ts.st.UpsertPipeline("keep", "y")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	rid, err := ts.st.CreateRun(pid, "manual", "")
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := ts.st.AddLog(rid, "s", "line"); err != nil {
			t.Fatalf("add log: %v", err)
		}
	}
	cid, err := ts.st.CreateCanary(store.CanaryRelease{
		Name: "app", Namespace: "ns", StableImage: "a:1", CanaryImage: "a:2",
	})
	if err != nil {
		t.Fatalf("create canary: %v", err)
	}
	if err := ts.st.InsertCanaryEvent(cid, "observing", "tick"); err != nil {
		t.Fatalf("insert event: %v", err)
	}
	if err := ts.st.AddAuditEvent(store.AuditEvent{Actor: "a", Action: "act", Target: "t", Outcome: "ok"}); err != nil {
		t.Fatalf("add audit event: %v", err)
	}

	// Clock one year in the future: everything is older than a 1d cutoff.
	ts.s.NowFn = func() time.Time { return time.Now().UTC().Add(365 * 24 * time.Hour) }
	ts.s.Retention = RetentionPolicy{Spec: "1d", Age: 24 * time.Hour}
	n, err := ts.s.RetentionTick()
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if n != 4 {
		t.Fatalf("purged %d rows, want 4 (2 logs + 1 canary event + 1 audit event)", n)
	}
	if logs, _ := ts.st.ListLogs(rid, "s", 0, 0); len(logs) != 0 {
		t.Fatalf("%d logs left, want 0", len(logs))
	}
	if ev, _ := ts.st.EventsOf(cid); len(ev) != 0 {
		t.Fatalf("%d canary events left, want 0", len(ev))
	}

	// Young data with a recent-past clock survives the same policy.
	rid2, err := ts.st.CreateRun(pid, "manual", "")
	if err != nil {
		t.Fatalf("create run 2: %v", err)
	}
	if _, err := ts.st.AddLog(rid2, "s", "young"); err != nil {
		t.Fatalf("add young log: %v", err)
	}
	ts.s.NowFn = func() time.Time { return time.Now().UTC().Add(-time.Hour) }
	n, err = ts.s.RetentionTick()
	if err != nil {
		t.Fatalf("tick 2: %v", err)
	}
	if n != 0 {
		t.Fatalf("purged %d rows for young data, want 0", n)
	}
	if logs, _ := ts.st.ListLogs(rid2, "s", 0, 0); len(logs) != 1 {
		t.Fatalf("young logs = %d, want 1", len(logs))
	}
}

// TestRetentionTickKeepLast (P7⑧): keep-last purges all but the keep
// most-recent runs' logs and all but the keep most-recent releases' events.
func TestRetentionTickKeepLast(t *testing.T) {
	ts := newTestScheduler(t)
	pid, err := ts.st.UpsertPipeline("keep", "y")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	rids := make([]int64, 5)
	for i := range rids {
		var err error
		if rids[i], err = ts.st.CreateRun(pid, "manual", ""); err != nil {
			t.Fatalf("create run %d: %v", i, err)
		}
		if _, err := ts.st.AddLog(rids[i], "s", "line"); err != nil {
			t.Fatalf("add log: %v", err)
		}
	}
	cids := make([]int64, 3)
	for i, name := range []string{"a", "b", "c"} {
		var err error
		if cids[i], err = ts.st.CreateCanary(store.CanaryRelease{
			Name: name, Namespace: "ns", StableImage: "a:1", CanaryImage: "a:2",
		}); err != nil {
			t.Fatalf("create canary %s: %v", name, err)
		}
		if err := ts.st.InsertCanaryEvent(cids[i], "observing", "tick"); err != nil {
			t.Fatalf("insert event: %v", err)
		}
	}
	for i := 0; i < 5; i++ {
		if err := ts.st.AddAuditEvent(store.AuditEvent{Actor: "a", Action: "act", Target: "t", Outcome: "ok"}); err != nil {
			t.Fatalf("add audit event %d: %v", i, err)
		}
	}

	ts.s.Retention = RetentionPolicy{Spec: "runs=2", Keep: 2}
	n, err := ts.s.RetentionTick()
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	// 5 runs keep 2 → 3 logs purged; 3 releases keep 2 → 1 event purged;
	// 5 audit events keep 2 → 3 events purged.
	if n != 7 {
		t.Fatalf("purged %d rows, want 7 (3 logs + 1 event + 3 audit events)", n)
	}
	if logs, _ := ts.st.ListLogs(rids[0], "s", 0, 0); len(logs) != 0 {
		t.Fatalf("oldest run still has %d logs", len(logs))
	}
	if logs, _ := ts.st.ListLogs(rids[4], "s", 0, 0); len(logs) != 1 {
		t.Fatalf("newest run lost its log (%d left)", len(logs))
	}
	if ev, _ := ts.st.EventsOf(cids[0]); len(ev) != 0 {
		t.Fatalf("oldest release still has %d events", len(ev))
	}
	if ev, _ := ts.st.EventsOf(cids[2]); len(ev) != 1 {
		t.Fatalf("newest release lost its event (%d left)", len(ev))
	}
	audit, err := ts.st.ListAuditEvents(store.AuditFilter{})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(audit) != 2 {
		t.Fatalf("%d audit events left, want 2 (keep-last)", len(audit))
	}
}
