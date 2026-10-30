// Package notify delivers webhook notifications for pipeline runs (P7⑦).
//
// One Event (a flat JSON object) is POSTed to every configured webhook URL.
// Send never blocks the pipeline: callers (the scheduler) invoke it
// asynchronously, and send failures are returned (and logged by the caller)
// without ever affecting a run's status. Standard library only.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Event is the webhook notification payload (P7⑦).
type Event struct {
	Pipeline   string `json:"pipeline"`
	RunID      int64  `json:"run_id"`
	Status     string `json:"status"` // success | failed | canceled | canary_rolled_back
	PR         int    `json:"pr"`     // 0 when the run was not triggered by a PR
	URL        string `json:"url,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
}

// WebhookSender POSTs an Event as JSON to one or more webhook URLs.
type WebhookSender struct {
	Client *http.Client
}

// NewWebhookSender returns a WebhookSender with a 10s request timeout.
func NewWebhookSender() *WebhookSender {
	return &WebhookSender{Client: &http.Client{Timeout: 10 * time.Second}}
}

// maxBodyDrain caps how much of a response body is drained before the
// connection is closed (a hostile endpoint must not hang us).
const maxBodyDrain = 1 << 20 // 1 MiB

// Send marshals ev once and POSTs it as JSON to each URL in urls.
//
// It returns exactly one error per input URL: nil on a 2xx response, the
// transport error otherwise, or "notify: webhook <url>: HTTP <status>" for a
// non-2xx status. Empty URL entries are skipped (nil error). Send never
// panics on a dead URL and never logs; callers log the returned errors.
func (s *WebhookSender) Send(ctx context.Context, urls []string, ev Event) []error {
	body, err := json.Marshal(ev)
	if err != nil {
		out := make([]error, len(urls))
		for i := range out {
			out[i] = fmt.Errorf("notify: marshal event: %w", err)
		}
		return out
	}

	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}

	out := make([]error, len(urls))
	for i, raw := range urls {
		u := strings.TrimSpace(raw)
		if u == "" {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
		if err != nil {
			out[i] = fmt.Errorf("notify: webhook %s: %w", raw, err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			out[i] = fmt.Errorf("notify: webhook %s: %w", raw, err)
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyDrain))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			out[i] = fmt.Errorf("notify: webhook %s: HTTP %d", raw, resp.StatusCode)
		}
	}
	return out
}
