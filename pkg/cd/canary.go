package cd

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flowstallion/flowstallion/pkg/store"
)

// releaseLocks is the process-wide per-release lock pool (K1). It must be
// package-level — not a Controller field — because the race is between
// separate Controller instances (the API's rollback controller, the
// scheduler's TickAll controller, and the per-step executor controllers),
// each created independently.
//
// It is a fixed stripe pool, not a map keyed by release id: release ids
// hash into one of releaseLockStripes mutexes, so the pool never grows with
// the number of ever-seen releases (the old sync.Map grew unboundedly and was
// never pruned). Two ids that share a stripe are serialized against each
// other — safe, just marginally less parallel, which is irrelevant for a
// self-hosted scheduler. The fixed pool also avoids the delete-while-another-
// goroutine-is-acquiring race that any "drop the lock when terminal" scheme
// would introduce.
var releaseLocks [releaseLockStripes]sync.Mutex

// releaseLockStripes is the stripe count. Larger = fewer cross-release
// serializations but more memory; 64 is ample for a self-hosted scheduler.
const releaseLockStripes = 64

// lockRelease acquires the striped mutex for the given release id and returns
// its unlock function. Callers defer the returned function. The lock spans
// the whole state-machine step (including kubectl calls) so that two drivers
// can never interleave cluster mutations on the same release. All calls for a
// given id hash to the same stripe, so per-release serialization is preserved.
func lockRelease(id int64) func() {
	mu := &releaseLocks[int(uint64(id)%releaseLockStripes)]
	mu.Lock()
	return mu.Unlock
}

// DefaultMaxProbeFailures is the number of consecutive readiness/metrics
// probe failures tolerated before a release is rolled back (or failed, while
// still applying). A single blip does not kill a release.
const DefaultMaxProbeFailures = 3

// DefaultApplyTimeout bounds the applying (waiting-ready) phase. A canary
// that never becomes ready (crash-looping image, unschedulable pod) must
// roll back instead of pinning the (name, namespace) slot forever (B-1).
const DefaultApplyTimeout = 5 * time.Minute

// Default canary observation parameters shared by the API create endpoint
// (pkg/api) and the scheduler-side k8s_canary executor (P7⑤).
const (
	DefaultReplicas   = 2
	DefaultPort       = 8080
	DefaultThreshold  = 0.3
	DefaultMinSamples = 20
	DefaultWarmupS    = 10.0
	DefaultObserveS   = 20.0
)

// Controller drives canary releases: it applies the manifests, watches the
// canary Deployment's readiness, scrapes the app's built-in /metrics through
// the API-server service proxy, and auto-rolls back (or promotes) based on
// the error-rate threshold.
//
// All kubectl I/O goes through the Kubectl interface so the state machine is
// unit-testable without a cluster; the clock is injectable the same way.
type Controller struct {
	Store   *store.Store
	Kubectl Kubectl
	// Now returns the current time (defaults to time.Now).
	Now func() time.Time
	// ApplyTimeout bounds the applying phase (B-1). Zero uses
	// DefaultApplyTimeout.
	ApplyTimeout time.Duration
	// MaxProbeFailures overrides DefaultMaxProbeFailures when > 0 (P7⑤:
	// k8s_canary steps expose canary.probe_failures).
	MaxProbeFailures int
}

// NewController builds a Controller with the real clock.
func NewController(st *store.Store, k Kubectl) *Controller {
	return &Controller{Store: st, Kubectl: k, Now: time.Now}
}

// applyTimeout returns the effective applying-phase timeout.
func (c *Controller) applyTimeout() time.Duration {
	if c.ApplyTimeout > 0 {
		return c.ApplyTimeout
	}
	return DefaultApplyTimeout
}

// probeLimit returns the effective consecutive-probe-failure threshold.
func (c *Controller) probeLimit() int {
	if c.MaxProbeFailures > 0 {
		return c.MaxProbeFailures
	}
	return DefaultMaxProbeFailures
}

// TickAll advances every non-terminal release one step. Errors are logged
// and never abort the loop: one broken release must not stall the others.
func (c *Controller) TickAll() {
	actives, err := c.Store.ActiveCanaries()
	if err != nil {
		log.Printf("cd: list active canaries: %v", err)
		return
	}
	for _, r := range actives {
		if err := c.Advance(r.ID); err != nil {
			log.Printf("cd: advance canary %d: %v", r.ID, err)
		}
	}
}

// Advance moves one release forward by a single state-machine step.
//
// K1: the whole step runs under the process-wide per-release lock so that
// the different drivers (API rollback, TickAll, per-step executor) can never
// interleave their kubectl calls or state writes for one release. The
// release is re-read AFTER taking the lock, and every state transition is a
// CAS (SetCanaryStateIf) against the state read under the lock. If the CAS
// loses (ErrCanaryStateConflict), the error is logged and returned; the
// outer tick/loop re-reads and re-decides on the next cycle.
func (c *Controller) Advance(id int64) error {
	unlock := lockRelease(id)
	defer unlock()

	r, err := c.Store.GetCanary(id)
	if err != nil {
		return err
	}
	var stepErr error
	switch r.State {
	case store.CanaryPending:
		stepErr = c.advancePending(&r)
	case store.CanaryApplying:
		stepErr = c.advanceApplying(&r)
	case store.CanaryReady:
		stepErr = c.advanceReady(&r)
	case store.CanaryObserving:
		stepErr = c.advanceObserving(&r)
	case store.CanaryPromoting:
		stepErr = c.advancePromoting(&r)
	default:
		stepErr = nil // terminal states are stable
	}
	if errors.Is(stepErr, store.ErrCanaryStateConflict) {
		log.Printf("cd: canary %d: state conflict (expected %q); a concurrent driver moved it, retry next cycle", id, r.State)
	}
	return stepErr
}

func (c *Controller) spec(r *store.CanaryRelease) CanarySpec {
	return CanarySpec{
		Name:        r.Name,
		Namespace:   r.Namespace,
		StableImage: r.StableImage,
		CanaryImage: r.CanaryImage,
		Replicas:    r.Replicas,
		Port:        r.Port,
	}
}

// strategyFor resolves a release's persisted strategy identifier to its
// implementation (empty/unknown -> canary, the legacy default).
func strategyFor(r *store.CanaryRelease) Strategy {
	return StrategyFor(r.Strategy)
}

// altNameOf is the strategy-specific alternate object name for a release
// ("<name>-canary" for the canary strategy, "<name>-alt" for blue-green).
func altNameOf(r *store.CanaryRelease) string {
	return strategyFor(r).AltName(r.Name)
}

// advancePending: pending -> applying. Applies the namespace, stable
// Deployment/Service and canary Deployment/Service. A single failed apply
// is retried on the next tick; probeLimit() consecutive failures mark
// the release failed (nothing exists to roll back to).
func (c *Controller) advancePending(r *store.CanaryRelease) error {
	st := strategyFor(r)
	out, err := c.Kubectl.Run([]string{"apply", "-f", "-"},
		RenderReleaseManifests(c.spec(r), st.AltName(r.Name), st.ID(), st.AltReplicas(r.Replicas)))
	if err != nil {
		return c.probeFailed(r, "apply", "apply", err, false)
	}
	c.logEvent(r, store.CanaryApplying, map[string]any{
		"phase": "apply", "output": truncate(out, 200),
	})
	if err := c.Store.SetCanaryStateIf(r.ID, store.CanaryApplying, "", "", r.State); err != nil {
		return err
	}
	// B-1: stamp when we entered the applying phase; the timeout below is
	// measured from here (survives restarts).
	return c.Store.SetApplyingSince(r.ID, c.now())
}

// advanceApplying: applying -> canary_ready once the canary Deployment has
// at least one ready replica. Probe failures are counted; probeLimit()
// in a row rolls back.
func (c *Controller) advanceApplying(r *store.CanaryRelease) error {
	// B-1: apply is one-shot; if the canary never becomes ready within
	// ApplyTimeout, roll back (a crash-looping image must not pin the
	// (name, namespace) slot forever).
	if r.ApplyingSince == "" {
		// Self-heal: a crash between the state transition and the stamp
		// (or a row created before the column existed) left no reference
		// point; stamp now so the timeout can run at all.
		r.ApplyingSince = c.now()
		if err := c.Store.SetApplyingSince(r.ID, r.ApplyingSince); err != nil {
			return err
		}
	}
	if since, perr := time.Parse(time.RFC3339, r.ApplyingSince); perr == nil {
		if c.Now().Sub(since) > c.applyTimeout() {
			return c.rollback(r, fmt.Sprintf(
				"canary not ready within %s (applying timeout)", c.applyTimeout()))
		}
	}
	out, err := c.Kubectl.Run(altDeployArgs(r), "")
	if err != nil {
		return c.probeFailed(r, "waiting-ready", "canary readiness", err, true)
	}
	var dep deployJSON
	if json.Unmarshal([]byte(out), &dep) != nil {
		return c.probeFailed(r, "waiting-ready", "canary readiness",
			fmt.Errorf("unparseable deploy json: %.120s", out), true)
	}
	if dep.Status.ReadyReplicas < 1 {
		c.logEvent(r, store.CanaryApplying, map[string]any{
			"phase":   "waiting-ready",
			"ready":   dep.Status.ReadyReplicas,
			"desired": dep.Spec.Replicas,
		})
		return nil
	}
	_ = c.Store.ResetScrapeFailures(r.ID)
	if err := c.Store.SetCanaryStart(r.ID, c.now()); err != nil {
		return err
	}
	c.logEvent(r, store.CanaryReady, map[string]any{
		"phase": "ready", "ready_replicas": dep.Status.ReadyReplicas,
	})
	return c.Store.SetCanaryStateIf(r.ID, store.CanaryReady, "", "", r.State)
}

// advanceReady: canary_ready -> observing (the watch window starts at
// canary_ready, stamped in advanceApplying).
func (c *Controller) advanceReady(r *store.CanaryRelease) error {
	c.logEvent(r, store.CanaryObserving, map[string]any{"phase": "observe-start"})
	return c.Store.SetCanaryStateIf(r.ID, store.CanaryObserving, "", "", r.State)
}

// advanceObserving: observing -> promoting | rolled_back.
//
//  1. Readiness re-check: a canary that stops being ready after warmup is
//     broken regardless of metrics.
//  2. Metrics scrape: the error rate over the window since the baseline
//     exceeds the threshold with enough delta samples -> rollback.
//  3. Window end (warmup + observe): promote if healthy (or if fewer than
//     min_samples delta samples were seen — a healthy canary with low
//     traffic must not block forever).
func (c *Controller) advanceObserving(r *store.CanaryRelease) error {
	start, err := time.Parse(time.RFC3339, r.CanaryStart)
	if err != nil || r.CanaryStart == "" {
		start = c.Now()
	}
	age := c.Now().Sub(start).Seconds()

	// 1. Readiness.
	depOut, err := c.Kubectl.Run(altDeployArgs(r), "")
	if err != nil {
		return c.probeFailed(r, "observing", "canary readiness", err, true)
	}
	var dep deployJSON
	if json.Unmarshal([]byte(depOut), &dep) != nil {
		return c.probeFailed(r, "observing", "canary readiness",
			fmt.Errorf("unparseable deploy json: %.120s", depOut), true)
	}
	if dep.Status.ReadyReplicas < 1 {
		if age >= r.WarmupS {
			// F-2: a single readiness dip after warmup (OOM kill,
			// eviction, probe flake) must not kill the release: require
			// probeLimit() consecutive not-ready ticks.
			return c.probeFailed(r, "observing", "canary readiness",
				fmt.Errorf("canary not ready at age %.1fs (ready_replicas=%d)",
					age, dep.Status.ReadyReplicas), true)
		}
		// Within warmup the pods may still be starting; just note it.
		c.logEvent(r, store.CanaryObserving, map[string]any{
			"phase": "observing", "age_s": round1(age), "note": "canary not ready yet",
		})
		return nil
	}

	// 2. Metrics scrape.
	out, err := c.Kubectl.Run(altMetricsArgs(r), "")
	if err != nil {
		return c.probeFailed(r, "observing", "metrics scrape", err, true)
	}
	var m metricsResp
	if json.Unmarshal([]byte(out), &m) != nil {
		return c.probeFailed(r, "observing", "metrics parse",
			fmt.Errorf("unparseable metrics: %.120s", out), true)
	}
	if m.Kind == "Status" {
		// The API server answered its own status document instead of
		// proxying to the service: bad path or unreachable endpoint.
		return c.probeFailed(r, "observing", "metrics scrape",
			fmt.Errorf("cluster status response, not app metrics: %.200s", out), true)
	}
	if err := c.Store.ResetScrapeFailures(r.ID); err != nil {
		return err
	}

	// m-3: the error rate is measured on the delta since the baseline
	// (counters at canary_ready), not on cumulative totals, so traffic
	// that accumulated before the window cannot dilute a bad release.
	if (r.BaselineRequests == 0 && r.BaselineErrors == 0) ||
		m.Requests < r.BaselineRequests || m.Errors < r.BaselineErrors {
		// First scrape after canary_ready (or a pod restart reset the
		// counters): (re)anchor the baseline.
		if err := c.Store.SetCanaryBaseline(r.ID, m.Requests, m.Errors); err != nil {
			return err
		}
		r.BaselineRequests, r.BaselineErrors = m.Requests, m.Errors
	}
	windowReq := m.Requests - r.BaselineRequests
	windowErr := m.Errors - r.BaselineErrors
	var rate float64
	if windowReq > 0 {
		rate = float64(windowErr) / float64(windowReq)
	}
	if err := c.Store.SetLastMetrics(r.ID, rate, m.Requests, m.Errors); err != nil {
		return err
	}
	c.logEvent(r, store.CanaryObserving, map[string]any{
		"phase": "observing", "age_s": round1(age),
		"requests": m.Requests, "errors": m.Errors,
		"window_requests": windowReq, "window_errors": windowErr,
		"err_rate": round4(rate), "version": m.Version,
	})

	// 3. Decision.
	enough := windowReq >= int64(r.MinSamples)
	if enough && rate > r.Threshold {
		return c.rollback(r, fmt.Sprintf(
			"error rate %.3f > threshold %.2f (%d window req, %d err)",
			rate, r.Threshold, windowReq, windowErr))
	}
	if age >= r.WarmupS+r.ObserveS {
		return c.beginPromote(r)
	}
	return nil
}

// beginPromote: observing -> promoting. Switches the stable Service
// selector to the alternate pods and persists the (non-terminal, re-entrant)
// promoting state before the destructive steps, so a crash in between is
// replayed instead of stranding the cluster half-promoted (m-5).
func (c *Controller) beginPromote(r *store.CanaryRelease) error {
	st := strategyFor(r)
	if _, err := c.Kubectl.Run([]string{"apply", "-f", "-"},
		RenderSwitchService(c.spec(r), st.AltName(r.Name), st.ID())); err != nil {
		return c.probeFailed(r, "promoting", "apply promote service", err, false)
	}
	if err := c.Store.SetCanaryStateIf(r.ID, store.CanaryPromoting, "", "", r.State); err != nil {
		return err
	}
	c.logEvent(r, store.CanaryPromoting, map[string]any{"phase": "promote-start"})
	return nil
}

// advancePromoting: promoting -> promoted. Scales the alternate up to the
// full replica count (a no-op for blue-green, where the alternate already
// runs at full size) and deletes the stable Deployment. Replays safely:
// scale is idempotent and delete tolerates the stable deployment already
// being gone.
func (c *Controller) advancePromoting(r *store.CanaryRelease) error {
	if _, err := c.Kubectl.Run(
		[]string{"-n", r.Namespace, "scale", "deploy/" + altNameOf(r),
			"--replicas=" + strconv.Itoa(r.Replicas)}, ""); err != nil {
		return c.probeFailed(r, "promoting", "scale canary", err, false)
	}
	if _, err := c.Kubectl.Run(
		[]string{"-n", r.Namespace, "delete", "deploy", r.Name}, ""); err != nil {
		if !strings.Contains(err.Error(), "NotFound") {
			return c.probeFailed(r, "promoting", "delete stable", err, false)
		}
	}
	if err := c.Store.ResetScrapeFailures(r.ID); err != nil {
		return err
	}
	c.logEvent(r, store.CanaryPromoted, map[string]any{"phase": "promote"})
	return c.Store.SetCanaryStateIf(r.ID, store.CanaryPromoted,
		"promoted: canary healthy for full window", c.now(), r.State)
}

// rollback deletes the alternate Deployment and Service; the stable
// Deployment was never touched, so traffic keeps flowing on it.
//
// From the promoting state the stable Service selector already points at
// the alternate pods (beginPromote), so deleting the alternate objects
// first would strand traffic on deleted pods (F-1). Restore the stable
// selector before the deletions; best effort, mirroring the probe-failure
// recovery path.
func (c *Controller) rollback(r *store.CanaryRelease, reason string) error {
	var notes []string
	if r.State == store.CanaryPromoting {
		if _, err := c.Kubectl.Run([]string{"apply", "-f", "-"}, RenderStableService(c.spec(r))); err != nil {
			notes = append(notes, "restore stable svc: "+err.Error())
		}
	}
	alt := altNameOf(r)
	if _, err := c.Kubectl.Run(
		[]string{"-n", r.Namespace, "delete", "deploy", alt}, ""); err != nil {
		notes = append(notes, "delete deploy: "+err.Error())
	}
	if _, err := c.Kubectl.Run(
		[]string{"-n", r.Namespace, "delete", "svc", alt}, ""); err != nil {
		notes = append(notes, "delete svc: "+err.Error())
	}
	detail := map[string]any{"phase": "rollback", "reason": reason}
	if len(notes) > 0 {
		detail["delete_warnings"] = notes
	}
	c.logEvent(r, store.CanaryRolledBack, detail)
	return c.Store.SetCanaryStateIf(r.ID, store.CanaryRolledBack, reason, c.now(), r.State)
}

// Rollback forces a release to rolled_back by id (P7⑤: scheduler-side step
// cancel/timeout path; P7⑧: operator API). Terminal releases are left
// untouched.
//
// K1: takes the process-wide per-release lock and re-reads the release
// under it, so the terminal check and the forced transition are race-free
// against every other driver (TickAll / executor / a concurrent rollback).
func (c *Controller) Rollback(id int64, reason string) error {
	unlock := lockRelease(id)
	defer unlock()

	r, err := c.Store.GetCanary(id)
	if err != nil {
		return err
	}
	if store.CanaryTerminal(r.State) {
		return nil
	}
	if err := c.rollback(&r, reason); err != nil {
		if errors.Is(err, store.ErrCanaryStateConflict) {
			log.Printf("cd: canary %d: rollback conflict (expected %q); a concurrent driver moved it", id, r.State)
		}
		return err
	}
	return nil
}

// fail marks a release failed (terminal) with the given reason.
func (c *Controller) fail(r *store.CanaryRelease, reason string) error {
	c.logEvent(r, store.CanaryFailed, map[string]any{"phase": "failed", "reason": reason})
	return c.Store.SetCanaryStateIf(r.ID, store.CanaryFailed, reason, c.now(), r.State)
}

// probeFailed counts one failed probe. After probeLimit() consecutive
// failures the release ends: rolled back when a canary exists and traffic
// must be sent back to stable (rollback=true), or failed when nothing was
// applied yet or the cluster is mid-promote (rollback=false).
func (c *Controller) probeFailed(r *store.CanaryRelease, phase, what string, err error, rollback bool) error {
	n, err2 := c.Store.BumpScrapeFailures(r.ID)
	if err2 != nil {
		return err2
	}
	c.logEvent(r, r.State, map[string]any{
		"phase": phase + "-probe-failed", "probe": what,
		"error": err.Error(), "consecutive": n,
	})
	if n >= c.probeLimit() {
		msg := fmt.Sprintf("%s failed %d consecutive times: %s", what, n, err.Error())
		if rollback {
			return c.rollback(r, msg)
		}
		if r.State == store.CanaryPromoting {
			// F-1: beginPromote may have already switched the stable
			// Service selector to the canary pods. Restore the stable
			// selector before declaring failure so traffic can reach the
			// stable Deployment again; best effort — the release fails
			// either way, and the operator can re-apply manually.
			if _, rerr := c.Kubectl.Run([]string{"apply", "-f", "-"}, RenderStableService(c.spec(r))); rerr != nil {
				log.Printf("cd: canary %d: restore stable service selector: %v", r.ID, rerr)
			}
		}
		return c.fail(r, msg)
	}
	return nil
}

// logEvent appends a state-machine event. A failed insert is logged, not
// swallowed or fatal: the state machine's own progress must not depend on
// event persistence.
func (c *Controller) logEvent(r *store.CanaryRelease, state string, detail map[string]any) {
	if err := c.Store.InsertCanaryEvent(r.ID, state, eventDetail(detail)); err != nil {
		log.Printf("cd: canary %d: insert event (%s): %v", r.ID, state, err)
	}
}

func (c *Controller) now() string {
	return c.Now().UTC().Format(time.RFC3339)
}

func altDeployArgs(r *store.CanaryRelease) []string {
	return []string{"-n", r.Namespace, "get", "deploy", altNameOf(r), "-o", "json"}
}

func altMetricsArgs(r *store.CanaryRelease) []string {
	path := fmt.Sprintf("/api/v1/namespaces/%s/services/%s:%d/proxy/metrics",
		r.Namespace, altNameOf(r), r.Port)
	return []string{"get", "--raw", path}
}

// deployJSON is the subset of a Deployment JSON document we consume.
type deployJSON struct {
	Spec struct {
		Replicas int `json:"replicas"`
	} `json:"spec"`
	Status struct {
		Replicas      int `json:"replicas"`
		ReadyReplicas int `json:"readyReplicas"`
	} `json:"status"`
}

// metricsResp is the demoapp's built-in /metrics document.
type metricsResp struct {
	Kind     string  `json:"kind"`
	Version  string  `json:"version"`
	Requests int64   `json:"requests"`
	Errors   int64   `json:"errors"`
	Scrapes  int64   `json:"scrapes"`
	FailRate float64 `json:"fail_rate"`
	UptimeS  float64 `json:"uptime_s"`
}

func round1(v float64) float64 { return roundN(v, 10) }
func round4(v float64) float64 { return roundN(v, 10000) }

func roundN(v, scale float64) float64 {
	return float64(int64(v*scale+0.5)) / scale
}

// eventDetail JSON-encodes a detail map for canary_events.detail.
func eventDetail(v map[string]any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
