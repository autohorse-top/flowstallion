package scheduler

import (
	"log"
	"time"

	"github.com/flowstallion/flowstallion/pkg/pipeline"
	"github.com/flowstallion/flowstallion/pkg/schedule"
)

// CronTick is one pass of the schedule-trigger loop (P7③): it walks every
// stored pipeline and, for each `event: schedule` trigger, starts a run
// (trigger type "schedule") when its cron slot is due relative to the last
// recorded fire.
//
// Catch-up semantics: the last-fire watermark advances to the tick time
// (not to the due slot), so an outage spanning several slots produces at
// most ONE catch-up run, and a second tick in the same window cannot
// re-fire the missed slots. The watermark is persisted even when Trigger
// fails (e.g. the concurrency limit is reached), so a broken or saturated
// pipeline cannot re-fire on every tick; failures are logged. Unparseable
// pipeline YAML or cron expressions are skipped with a log line and never
// fail the whole tick.
func (s *Scheduler) CronTick() error {
	now := time.Now().UTC()
	if s.NowFn != nil {
		now = s.NowFn()
	}
	pipelines, err := s.Store.ListPipelines()
	if err != nil {
		return err
	}
	for _, p := range pipelines {
		pl, err := pipeline.ParseYAML([]byte(p.YAMLText))
		if err != nil {
			log.Printf("cron: pipeline %q has invalid yaml, skipping schedule scan: %v", p.Name, err)
			continue
		}
		for _, tr := range pl.Pipeline.Trigger {
			if tr.Event != "schedule" || tr.Cron == "" {
				continue
			}
			cron, err := schedule.Parse(tr.Cron)
			if err != nil {
				log.Printf("cron: pipeline %q has unparseable cron %q, skipping: %v", p.Name, tr.Cron, err)
				continue
			}
			key := p.Name + "|" + tr.Cron
			last, hasLast, err := s.Store.GetLastScheduleFire(key)
			if err != nil {
				return err
			}
			base := time.Time{}
			if hasLast {
				base = last
			}
			next, ok := cron.NextRun(base)
			if !ok {
				log.Printf("cron: pipeline %q cron %q matches no date (impossible schedule), not scheduling", p.Name, tr.Cron)
				continue
			}
			if now.Before(next) {
				continue
			}
			runID, triggerErr := s.Trigger(p.Name, "schedule", "")
			if triggerErr != nil {
				log.Printf("cron: pipeline %q scheduled run failed (slot consumed): %v", p.Name, triggerErr)
			} else {
				log.Printf("cron: scheduled run %d for pipeline %q (cron %q)", runID, p.Name, tr.Cron)
			}
			if err := s.Store.SetLastScheduleFire(key, now); err != nil {
				return err
			}
		}
	}
	return nil
}
