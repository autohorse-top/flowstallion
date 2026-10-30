// Package scheduler — webhook notification hooks (P7⑦).
//
// A run terminal state (success / failed / canceled) and a canary rollback
// emit a webhook notification to every endpoint listed in the pipeline's
// notifications block. Delivery is fire-and-forget: the payload is built
// from persisted state in a separate goroutine, and any failure is logged
// and swallowed — a broken webhook can never affect a run's status.
package scheduler

import (
	"context"
	"log"
	"strconv"

	"github.com/flowstallion/flowstallion/pkg/notify"
	"github.com/flowstallion/flowstallion/pkg/pipeline"
	"github.com/flowstallion/flowstallion/pkg/store"
)

// statusCanaryRolledBack is the Event.Status payload for canary rollback
// notifications (P7⑦).
const statusCanaryRolledBack = "canary_rolled_back"

// Notifier delivers a notification event to webhook endpoints. The scheduler
// package defines this interface (consumer-side) so it depends only on the
// method shape; pkg/notify's WebhookSender satisfies it. A nil Notifier
// disables notifications entirely.
type Notifier interface {
	Send(ctx context.Context, urls []string, ev notify.Event) []error
}

// notifyTerminal fires the webhook notification for a run that has just
// reached a terminal state (success / failed / canceled). The caller has
// already persisted the status, so the async reader sees consistent state.
// It never blocks the scheduler and never returns an error.
func (s *Scheduler) notifyTerminal(runID int64, status string) {
	go notifyEvent(s.Store, s.Notifier, s.Cfg.WebBaseURL, runID, status)
}

// notifyEvent builds the payload from persisted run/pipeline state and hands
// it to the Notifier. Every failure mode (missing run, missing pipeline,
// corrupt stored YAML, no notifications configured, send failure) is logged
// and swallowed.
func notifyEvent(st *store.Store, n Notifier, webBaseURL string, runID int64, status string) {
	if n == nil {
		return
	}

	run, err := st.GetRun(runID)
	if err != nil {
		log.Printf("notify: run %d: %v", runID, err)
		return
	}
	p, err := st.GetPipeline(run.PipelineID)
	if err != nil {
		log.Printf("notify: run %d: pipeline: %v", runID, err)
		return
	}
	spec, err := pipeline.ParseYAML([]byte(p.YAMLText))
	if err != nil {
		log.Printf("notify: run %d: parse stored spec: %v", runID, err)
		return
	}
	ntfs := spec.Pipeline.Notifications
	if len(ntfs) == 0 {
		return
	}

	urls := make([]string, len(ntfs))
	for i, nt := range ntfs {
		urls[i] = nt.URL
	}

	ev := notify.Event{
		Pipeline:   spec.Pipeline.Name,
		RunID:      runID,
		Status:     status,
		PR:         run.PR,
		FinishedAt: run.FinishedAt,
	}
	if webBaseURL != "" {
		ev.URL = webBaseURL + "/run/" + strconv.FormatInt(runID, 10)
	}

	errs := n.Send(context.Background(), urls, ev)
	for i, err := range errs {
		if err != nil {
			log.Printf("notify: run %d (%s) webhook %s: %v", runID, status, urls[i], err)
		}
	}
}
