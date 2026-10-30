// client.go: thin HTTP client for the FlowStallion scheduler API used by the
// flowstallion CLI. DTO field names must stay in sync with pkg/api/server.go.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// DTOs (mirror pkg/api)
// ---------------------------------------------------------------------------

type pipelineJSON struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type runJSON struct {
	ID         int64  `json:"id"`
	PipelineID int64  `json:"pipeline_id"`
	Status     string `json:"status"`
	Trigger    string `json:"trigger"`
	SourceRef  string `json:"source_ref"`
	// P7⑧: reason recorded on a rejected (policy-held) run; empty otherwise.
	RejectReason string `json:"reject_reason,omitempty"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
	CreatedAt    string `json:"created_at"`
}

type stepJSON struct {
	ID         int64             `json:"id"`
	StepID     string            `json:"step_id"`
	StepIndex  int               `json:"step_index"`
	Status     string            `json:"status"`
	Image      string            `json:"image"`
	Outputs    map[string]string `json:"outputs,omitempty"`
	StartedAt  string            `json:"started_at"`
	FinishedAt string            `json:"finished_at"`
}

type logJSON struct {
	Seq  int64  `json:"seq"`
	Line string `json:"line"`
	TS   string `json:"ts"`
}

// canaryJSON mirrors pkg/api's canary response (GET /api/canaries[/{id}]).
type canaryJSON struct {
	ID             int64   `json:"id"`
	Name           string  `json:"name"`
	Namespace      string  `json:"namespace"`
	StableImage    string  `json:"stable_image"`
	CanaryImage    string  `json:"canary_image"`
	Strategy       string  `json:"strategy"`
	SourceRef      string  `json:"source_ref,omitempty"`
	RunID          int64   `json:"run_id,omitempty"`
	Replicas       int     `json:"replicas"`
	Port           int     `json:"port"`
	Threshold      float64 `json:"threshold"`
	MinSamples     int     `json:"min_samples"`
	WarmupS        float64 `json:"warmup_s"`
	ObserveS       float64 `json:"observe_s"`
	State          string  `json:"state"`
	Reason         string  `json:"reason,omitempty"`
	LastErrRate    float64 `json:"last_err_rate"`
	LastRequests   int64   `json:"last_requests"`
	LastErrors     int64   `json:"last_errors"`
	ScrapeFailures int     `json:"scrape_failures"`
	CanaryStart    string  `json:"canary_start,omitempty"`
	CreatedAt      string  `json:"created_at"`
	FinishedAt     string  `json:"finished_at,omitempty"`
}

// canaryEventJSON mirrors the event rows of GET /api/canaries/{id}.
type canaryEventJSON struct {
	ID     int64  `json:"id"`
	TS     string `json:"ts"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

// apiError carries an HTTP error response from the scheduler.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message)
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

type client struct {
	base  string
	token string
	http  *http.Client
}

func newClient(server, token string) *client {
	return &client{
		base:  strings.TrimRight(server, "/"),
		token: token,
		http:  &http.Client{Timeout: 120 * time.Second},
	}
}

// doJSON performs an HTTP request with an optional JSON body, decodes the
// JSON response into out (if non-nil), and returns *apiError on HTTP errors.
func (c *client) doJSON(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		msg := strings.TrimSpace(string(data))
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		if resp.StatusCode == http.StatusUnauthorized && c.token != "" {
			msg += " (session expired or invalid — re-run `flowstallion login <url> -u <user> -p <pass>`)"
		}
		return &apiError{Status: resp.StatusCode, Message: msg}
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
