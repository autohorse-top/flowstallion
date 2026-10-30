// Package scheduler — CD step executor (k8s_canary / k8s_blue_green, P7⑤).
//
// CD steps are never dispatched to an agent: the scheduler drives the
// pkg/cd release state machine directly and synchronously, using the step's
// strategy (k8s_canary -> canary, k8s_blue_green -> blue_green). The release
// is run-bound (canary_releases.run_id) and therefore excluded from the
// background TickAll loop, so exactly one driver ever touches it. On step
// cancel/timeout the executor rolls the release back best-effort before
// returning, so a canceled run never leaves a half-rolled-out cluster.
package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/flowstallion/flowstallion/pkg/cd"
	"github.com/flowstallion/flowstallion/pkg/pipeline"
	"github.com/flowstallion/flowstallion/pkg/store"
)

// CanaryExecutor implements StepExecutor for CD steps (k8s_canary /
// k8s_blue_green, P7⑤).
type CanaryExecutor struct {
	Store   *store.Store
	Kubectl cd.Kubectl
	// Now returns the current time (defaults to time.Now; tests inject a
	// fake clock so the observation window can elapse instantly).
	Now func() time.Time
	// Poll is the delay between state-machine advances (default 1s).
	Poll time.Duration
	// Notifier delivers the canary_rolled_back webhook (P7⑦). Nil disables.
	Notifier Notifier
	// WebBaseURL is the web console base (no trailing slash) for the
	// notification payload "url" field (P7⑦). Empty → url omitted.
	WebBaseURL string
}

// NewCanaryExecutor builds a CanaryExecutor with the real clock and a 1s
// poll interval.
func NewCanaryExecutor(st *store.Store, k cd.Kubectl) *CanaryExecutor {
	return &CanaryExecutor{Store: st, Kubectl: k, Now: time.Now, Poll: time.Second}
}

// Execute runs a CD step (k8s_canary / k8s_blue_green) until its release
// reaches a terminal state.
//
// The step's image must be a concrete image (no template placeholders —
// rejected at parse time). stable_image and replica count are seeded from
// the live stable Deployment. The step succeeds iff the release is
// promoted; rolled_back / failed map to a step error carrying the release
// reason.
func (e *CanaryExecutor) Execute(ctx context.Context, step pipeline.StepDef, runID int64, env map[string]string) error {
	_ = env // CD steps are driven by the scheduler, not an agent shell
	lw := LogWriterFrom(ctx)

	now := e.Now
	if now == nil {
		now = time.Now
	}
	poll := e.Poll
	if poll <= 0 {
		poll = time.Second
	}

	k := e.Kubectl
	if step.K8sContext != "" {
		k = cd.ContextKubectl{Inner: k, Context: step.K8sContext}
	}

	// The step type selects the release strategy.
	strategyID := "canary"
	if step.Type == "k8s_blue_green" {
		strategyID = "blue_green"
	}

	// 1) Seed from the live stable deployment.
	stableImage, replicas, err := cd.StableDeployment(k, step.Namespace, step.Deployment)
	if err != nil {
		return fmt.Errorf("%s: %w", step.Type, err)
	}
	if replicas < 1 {
		replicas = cd.DefaultReplicas
	}
	fmt.Fprintf(lw, "%s: stable %s/%s image=%s replicas=%d, alt image=%s (strategy=%s)\n",
		step.Type, step.Namespace, step.Deployment, stableImage, replicas, step.Image, strategyID)

	// 2) Create the run-bound release.
	sourceRef := ""
	if run, rerr := e.Store.GetRun(runID); rerr == nil {
		sourceRef = run.SourceRef
	}
	id, err := e.Store.CreateCanary(store.CanaryRelease{
		Name:        step.Deployment,
		Namespace:   step.Namespace,
		StableImage: stableImage,
		CanaryImage: step.Image,
		Strategy:    strategyID,
		SourceRef:   sourceRef,
		RunID:       runID,
		Replicas:    replicas,
		Port:        cd.DefaultPort,
		Threshold:   cd.DefaultThreshold,
		MinSamples:  cd.DefaultMinSamples,
		WarmupS:     cd.DefaultWarmupS,
		ObserveS:    cd.DefaultObserveS,
	})
	if err != nil {
		return fmt.Errorf("%s: create release: %w", step.Type, err)
	}
	e.writeOutputs(runID, step.ID, id, store.CanaryPending, stableImage, step.CanaryWeight)
	fmt.Fprintf(lw, "%s: release %d created (run %d, source_ref=%s)\n", step.Type, id, runID, sourceRef)

	// 3) Drive the state machine until terminal. Zero values fall back to
	// the pkg/cd defaults (canary.timeout / canary.probe_failures).
	ctl := &cd.Controller{
		Store:            e.Store,
		Kubectl:          k,
		Now:              now,
		ApplyTimeout:     time.Duration(step.CanaryTimeout) * time.Second,
		MaxProbeFailures: step.CanaryProbeFailures,
	}

	lastLogged := ""
	for {
		if err := ctl.Advance(id); err != nil {
			if !errors.Is(err, store.ErrCanaryStateConflict) {
				// K1: a state conflict is benign (a concurrent driver moved
				// the release); the re-read below picks up the new state.
				// Only log unexpected errors.
				log.Printf("canary_executor: advance release %d: %v", id, err)
			}
		}
		rel, err := e.Store.GetCanary(id)
		if err != nil {
			return fmt.Errorf("%s: read release %d: %w", step.Type, id, err)
		}
		if rel.State != lastLogged {
			lastLogged = rel.State
			line := fmt.Sprintf("%s: release %d -> %s", step.Type, id, rel.State)
			if rel.Reason != "" {
				line += " (" + rel.Reason + ")"
			}
			fmt.Fprintln(lw, line)
		}
		e.writeOutputs(runID, step.ID, id, rel.State, stableImage, step.CanaryWeight)
		if store.CanaryTerminal(rel.State) {
			if rel.State == store.CanaryPromoted {
				return nil
			}
			if rel.State == store.CanaryRolledBack {
				// P7⑦: the release is already rolled back (persisted above);
				// notify before the step error propagates to the run.
				go notifyEvent(e.Store, e.Notifier, e.WebBaseURL, runID, statusCanaryRolledBack)
			}
			return fmt.Errorf("%s: release %d %s: %s", step.Type, id, rel.State, rel.Reason)
		}
		select {
		case <-ctx.Done():
			fmt.Fprintf(lw, "%s: context done (%v); rolling back release %d\n", step.Type, ctx.Err(), id)
			if rerr := ctl.Rollback(id, "step canceled or timed out; auto rollback"); rerr != nil {
				// Rollback itself failed: no canary_rolled_back notification
				// (the run-level "canceled"/"failed" webhook still fires).
				return fmt.Errorf("%s: rollback after cancel: %w (context: %v)", step.Type, rerr, ctx.Err())
			}
			// P7⑦: rollback persisted successfully; notify before returning.
			go notifyEvent(e.Store, e.Notifier, e.WebBaseURL, runID, statusCanaryRolledBack)
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// writeOutputs records the canary's progress in the run step's outputs
// (JSON), the same channel P7④ uses for docker_build image_ref. All values
// are strings: the API decodes step outputs into map[string]string, so any
// non-string value would fail to decode and vanish from the response.
func (e *CanaryExecutor) writeOutputs(runID int64, stepID string, releaseID int64, state, stableImage string, weight int) {
	if runID <= 0 {
		return
	}
	b, err := json.Marshal(map[string]string{
		"canary_release_id": strconv.FormatInt(releaseID, 10),
		"canary_state":      state,
		"stable_image":      stableImage,
		"canary_weight":     strconv.Itoa(weight),
	})
	if err != nil {
		log.Printf("canary_executor: marshal outputs: %v", err)
		return
	}
	if err := e.Store.SetRunStepOutputs(runID, stepID, string(b)); err != nil {
		log.Printf("canary_executor: write outputs for step %q: %v", stepID, err)
	}
}
