// Package api exposes the FlowStallion scheduler over HTTP (JSON + SSE) and
// implements the runner-agent protocol: the scheduler dispatches steps to
// agents, agents stream logs back and report completion.
//
// The Dispatcher holds an in-memory queue of steps awaiting a runner agent.
// It is single-node (one scheduler process); multi-agent horizontal scaling
// is a P2 concern.
package api

import (
	"fmt"
	"sync"
)

// Job is a step handed to a runner agent.
type Job struct {
	RunID    int64             `json:"run_id"`
	StepID   string            `json:"step_id"`
	Image    string            `json:"image"`
	Commands []string          `json:"commands"`
	Env      map[string]string `json:"env"`
	TimeoutS int               `json:"timeout_s"`
	// P7④: docker_build step fields (ignored by container steps).
	// Image holds the already-expanded target image reference.
	StepType   string `json:"step_type,omitempty"`  // "" | "docker_build"
	Dockerfile string `json:"dockerfile,omitempty"` // relative path, default "Dockerfile"
	Context    string `json:"context,omitempty"`    // build context, relative to agent CWD
	Push       bool   `json:"push,omitempty"`       // push target image after build
}

type jobResult struct {
	ok      bool
	message string
}

type pendingJob struct {
	job     Job
	claimed string
	done    chan jobResult
}

// Dispatcher holds the in-memory queue of steps awaiting a runner agent.
type Dispatcher struct {
	mu       sync.Mutex
	pending  map[string]*pendingJob // claimable
	inflight map[string]*pendingJob // claimed, awaiting finish
	order    []string               // pending keys, FIFO
}

// NewDispatcher creates an empty dispatcher.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		pending:  make(map[string]*pendingJob),
		inflight: make(map[string]*pendingJob),
	}
}

func jobKey(runID int64, stepID string) string {
	return fmt.Sprintf("%d:%s", runID, stepID)
}

// Enqueue registers a step for agent execution. It returns a channel that
// receives the agent's final result, or is closed (empty) if the job is
// dropped (step timeout / run cancel) before the agent finishes.
func (d *Dispatcher) Enqueue(j Job) <-chan jobResult {
	key := jobKey(j.RunID, j.StepID)
	d.mu.Lock()
	pj := &pendingJob{job: j, done: make(chan jobResult, 1)}
	d.pending[key] = pj
	d.order = append(d.order, key)
	d.mu.Unlock()
	return pj.done
}

// Claim returns the next unclaimed job (FIFO), marking it claimed by agent.
// A nil return means the queue is empty.
func (d *Dispatcher) Claim(agent string) *Job {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, key := range d.order {
		pj := d.pending[key]
		if pj.claimed != "" {
			continue
		}
		pj.claimed = agent
		d.order = append(d.order[:i], d.order[i+1:]...)
		delete(d.pending, key)
		d.inflight[key] = pj
		j := pj.job
		return &j
	}
	return nil
}

// Finish resolves an in-flight job. It reports whether the job was known.
func (d *Dispatcher) Finish(runID int64, stepID, status, message string) bool {
	ok := status == "success"
	res := jobResult{ok: ok, message: message}
	key := jobKey(runID, stepID)
	d.mu.Lock()
	pj, exists := d.inflight[key]
	delete(d.inflight, key)
	d.mu.Unlock()
	if !exists {
		return false
	}
	pj.done <- res
	return true
}

// Drop removes a job from both pending and inflight and closes its result
// channel so any waiter wakes up (used on step timeout / run cancel).
func (d *Dispatcher) Drop(runID int64, stepID string) {
	key := jobKey(runID, stepID)
	d.mu.Lock()
	if pj, ok := d.pending[key]; ok {
		for i, k := range d.order {
			if k == key {
				d.order = append(d.order[:i], d.order[i+1:]...)
				break
			}
		}
		delete(d.pending, key)
		close(pj.done)
	}
	if pj, ok := d.inflight[key]; ok {
		delete(d.inflight, key)
		close(pj.done)
	}
	d.mu.Unlock()
}

// PendingCount / InflightCount for observability.
func (d *Dispatcher) PendingCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.pending)
}

func (d *Dispatcher) InflightCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.inflight)
}
