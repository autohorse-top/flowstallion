package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// webhookRecorder captures POSTs for the sender tests.
type webhookRecorder struct {
	mu     sync.Mutex
	status int
	hits   int
	bodies []string
}

func (r *webhookRecorder) serve(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits++
	r.bodies = append(r.bodies, string(b))
	w.WriteHeader(r.status)
}

// startWebhook starts a recording test server answering with the given
// status and registers its shutdown with the test.
func startWebhook(t *testing.T, status int) (string, *webhookRecorder) {
	t.Helper()
	r := &webhookRecorder{status: status}
	ts := httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(ts.Close)
	return ts.URL, r
}

// TestEventJSON pins the exact wire format of the webhook payload: stable
// key order, "pr" always present (0 for non-PR runs), and omitempty on url /
// finished_at.
func TestEventJSON(t *testing.T) {
	full := Event{
		Pipeline:   "demo",
		RunID:      7,
		Status:     "success",
		PR:         3,
		URL:        "http://console.test/run/7",
		FinishedAt: "2026-01-02T03:04:05Z",
	}
	got, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"pipeline":"demo","run_id":7,"status":"success","pr":3,"url":"http://console.test/run/7","finished_at":"2026-01-02T03:04:05Z"}`
	if string(got) != want {
		t.Errorf("full event JSON = %s, want %s", got, want)
	}

	minimal := Event{Pipeline: "demo", RunID: 1, Status: "failed"}
	got, err = json.Marshal(minimal)
	if err != nil {
		t.Fatalf("marshal minimal: %v", err)
	}
	want = `{"pipeline":"demo","run_id":1,"status":"failed","pr":0}`
	if string(got) != want {
		t.Errorf("minimal event JSON = %s, want %s (pr=0 must be present, url/finished_at omitted)", got, want)
	}
}

// TestSendTableDriven covers the Send contract: 2xx vs non-2xx, multiple
// URLs, empty URL entries, dead endpoints, and a canceled context.
func TestSendTableDriven(t *testing.T) {
	t.Helper()

	ev := Event{
		Pipeline:   "demo",
		RunID:      7,
		Status:     "success",
		URL:        "http://console.test/run/7",
		FinishedAt: "2026-01-02T03:04:05Z",
	}
	wantBody, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	assertErrs := func(t *testing.T, errs []error, want []string) {
		t.Helper()
		if len(errs) != len(want) {
			t.Fatalf("Send returned %d errors, want %d (one per URL)", len(errs), len(want))
		}
		for i := range want {
			switch {
			case want[i] == "":
				if errs[i] != nil {
					t.Errorf("url[%d]: error = %v, want nil", i, errs[i])
				}
			case errs[i] == nil:
				t.Errorf("url[%d]: error = nil, want error containing %q", i, want[i])
			default:
				if !strings.Contains(errs[i].Error(), want[i]) {
					t.Errorf("url[%d]: error = %q, want it to contain %q", i, errs[i].Error(), want[i])
				}
			}
		}
	}

	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "http 200 -> nil error and exact body received",
			run: func(t *testing.T) {
				url, rec := startWebhook(t, http.StatusOK)
				errs := NewWebhookSender().Send(context.Background(), []string{url}, ev)
				assertErrs(t, errs, []string{""})
				rec.mu.Lock()
				defer rec.mu.Unlock()
				if rec.hits != 1 {
					t.Fatalf("server hits = %d, want 1", rec.hits)
				}
				if rec.bodies[0] != string(wantBody) {
					t.Errorf("body = %s, want %s", rec.bodies[0], wantBody)
				}
			},
		},
		{
			name: "http 500 -> error mentioning the status",
			run: func(t *testing.T) {
				url, _ := startWebhook(t, http.StatusInternalServerError)
				errs := NewWebhookSender().Send(context.Background(), []string{url}, ev)
				assertErrs(t, errs, []string{"HTTP 500"})
			},
		},
		{
			name: "http 404 -> error",
			run: func(t *testing.T) {
				url, _ := startWebhook(t, http.StatusNotFound)
				errs := NewWebhookSender().Send(context.Background(), []string{url}, ev)
				assertErrs(t, errs, []string{"HTTP 404"})
			},
		},
		{
			name: "two urls both 200 -> two nils, both servers saw the event",
			run: func(t *testing.T) {
				urlA, recA := startWebhook(t, http.StatusOK)
				urlB, recB := startWebhook(t, http.StatusCreated)
				errs := NewWebhookSender().Send(context.Background(), []string{urlA, urlB}, ev)
				assertErrs(t, errs, []string{"", ""})
				for _, rec := range []*webhookRecorder{recA, recB} {
					rec.mu.Lock()
					if rec.hits != 1 {
						t.Errorf("server hits = %d, want 1", rec.hits)
					}
					if len(rec.bodies) == 1 && rec.bodies[0] != string(wantBody) {
						t.Errorf("body = %s, want %s", rec.bodies[0], wantBody)
					}
					rec.mu.Unlock()
				}
			},
		},
		{
			name: "empty url entry is skipped",
			run: func(t *testing.T) {
				url, rec := startWebhook(t, http.StatusOK)
				errs := NewWebhookSender().Send(context.Background(), []string{"", url, "   "}, ev)
				assertErrs(t, errs, []string{"", "", ""})
				rec.mu.Lock()
				defer rec.mu.Unlock()
				if rec.hits != 1 {
					t.Fatalf("server hits = %d, want 1 (empty entries must be skipped)", rec.hits)
				}
			},
		},
		{
			name: "dead endpoint -> non-nil error, no panic",
			run: func(t *testing.T) {
				errs := NewWebhookSender().Send(context.Background(), []string{"http://127.0.0.1:1/hook"}, ev)
				assertErrs(t, errs, []string{"notify: webhook"})
			},
		},
		{
			name: "canceled context -> non-nil error",
			run: func(t *testing.T) {
				url, _ := startWebhook(t, http.StatusOK)
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				errs := NewWebhookSender().Send(ctx, []string{url}, ev)
				assertErrs(t, errs, []string{"notify: webhook"})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

// TestSendNoClientFallsBack: a zero-value sender must still work (the
// scheduler wiring may construct it ad hoc).
func TestSendNoClientFallsBack(t *testing.T) {
	ev := Event{Pipeline: "demo", RunID: 1, Status: "canceled"}
	url, rec := startWebhook(t, http.StatusOK)
	errs := (&WebhookSender{}).Send(context.Background(), []string{url}, ev)
	if len(errs) != 1 || errs[0] != nil {
		t.Fatalf("errs = %v, want [nil]", errs)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.hits != 1 {
		t.Errorf("hits = %d, want 1", rec.hits)
	}
}

// TestSendTimeoutHonoured bounds a hanging endpoint: the client timeout
// (here overridden to a short one) must turn into an error, not a hang.
func TestSendTimeoutHonoured(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond) // outlives the 50ms client timeout
	}))
	defer ts.Close()

	s := &WebhookSender{Client: &http.Client{Timeout: 50 * time.Millisecond}}
	start := time.Now()
	errs := s.Send(context.Background(), []string{ts.URL}, Event{Pipeline: "p", RunID: 1, Status: "success"})
	if len(errs) != 1 || errs[0] == nil {
		t.Fatalf("errs = %v, want a single timeout error", errs)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Send took %v; the 50ms client timeout was not honoured", d)
	}
}
