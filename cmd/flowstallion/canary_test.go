package main

import (
	"strings"
	"testing"
)

// TestFindCanaryForRun covers the 0/1/multiple-match cases: no canary bound to
// the run, exactly one, and several (highest id wins — the most recent
// release for the run).
func TestFindCanaryForRun(t *testing.T) {
	cases := []struct {
		name   string
		runs   []canaryJSON
		runID  int64
		wantID int64
		wantOK bool
	}{
		{name: "no canaries", runs: nil, runID: 7, wantOK: false},
		{
			name:  "no match",
			runs:  []canaryJSON{{ID: 1, RunID: 5}},
			runID: 7, wantOK: false,
		},
		{
			name:  "single match",
			runs:  []canaryJSON{{ID: 3, RunID: 7}, {ID: 9, RunID: 8}},
			runID: 7, wantID: 3, wantOK: true,
		},
		{
			name:  "multiple matches: highest id",
			runs:  []canaryJSON{{ID: 2, RunID: 7}, {ID: 9, RunID: 7}, {ID: 5, RunID: 8}},
			runID: 7, wantID: 9, wantOK: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := findCanaryForRun(tc.runs, tc.runID)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got.ID != tc.wantID {
				t.Fatalf("id = %d, want %d", got.ID, tc.wantID)
			}
		})
	}
}

func TestFormatCanaryReadback(t *testing.T) {
	t.Run("full", func(t *testing.T) {
		evs := make([]canaryEventJSON, 0, 25)
		for i := 1; i <= 25; i++ {
			evs = append(evs, canaryEventJSON{
				ID: int64(i), TS: "2026-10-26T00:00:00Z",
				State: "applying", Detail: "step " + strings.Repeat("x", 3) + string(rune('0'+i%10)),
			})
		}
		got := formatCanaryReadback(canaryJSON{
			ID: 7, Name: "demoapp", Namespace: "prod", RunID: 42,
			State:       "observing",
			Reason:      "err spike",
			Strategy:    "canary",
			LastErrRate: 0.12345, LastRequests: 100, LastErrors: 12,
			CanaryStart: "2026-10-26T00:00:00Z", FinishedAt: "2026-10-26T00:05:00Z",
		}, evs)

		var want strings.Builder
		want.WriteString("Canary #7  demoapp  (namespace prod, run 42)\n")
		want.WriteString("  strategy:   canary\n")
		want.WriteString("  state:      observing\n")
		want.WriteString("  reason:     err spike\n")
		want.WriteString("  err_rate:   0.1235 (requests 100, errors 12)\n")
		want.WriteString("  canary_start: 2026-10-26T00:00:00Z\n")
		want.WriteString("  finished_at:  2026-10-26T00:05:00Z\n")
		want.WriteString("  recent events (last 20):\n")
		// Only the last 20 of the 25 events are printed.
		for i := 6; i <= 25; i++ {
			want.WriteString("    2026-10-26T00:00:00Z  applying  ")
			want.WriteString("step " + strings.Repeat("x", 3) + string(rune('0'+i%10)) + "\n")
		}
		if got != want.String() {
			t.Fatalf("readback mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want.String())
		}
	})

	t.Run("no events, optional fields absent", func(t *testing.T) {
		got := formatCanaryReadback(canaryJSON{
			ID: 1, Name: "web", Namespace: "dev", RunID: 3,
			State: "pending", LastErrRate: 0, LastRequests: 0, LastErrors: 0,
		}, nil)
		want := "Canary #1  web  (namespace dev, run 3)\n" +
			"  strategy:   canary\n" +
			"  state:      pending\n" +
			"  err_rate:   0.0000 (requests 0, errors 0)\n" +
			"  recent events (last 20):\n" +
			"  (none)\n"
		if got != want {
			t.Fatalf("readback mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
		}
	})

	t.Run("blue-green strategy shown", func(t *testing.T) {
		got := formatCanaryReadback(canaryJSON{
			ID: 1, Name: "web", Namespace: "dev", RunID: 3,
			Strategy: "blue_green", State: "observing",
		}, nil)
		want := "Blue-Green #1  web  (namespace dev, run 3)\n" +
			"  strategy:   blue_green\n" +
			"  state:      observing\n" +
			"  err_rate:   0.0000 (requests 0, errors 0)\n" +
			"  recent events (last 20):\n" +
			"  (none)\n"
		if got != want {
			t.Fatalf("readback mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
		}
	})
}
