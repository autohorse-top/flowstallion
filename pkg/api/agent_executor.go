package api

import (
	"context"
	"errors"

	"github.com/flowstallion/flowstallion/pkg/pipeline"
	"github.com/flowstallion/flowstallion/pkg/scheduler"
)

// AgentExecutor is a scheduler.StepExecutor that dispatches each step to a
// runner agent through the Dispatcher and blocks (honoring ctx) until the
// agent reports the step outcome.
type AgentExecutor struct {
	D *Dispatcher
}

var _ scheduler.StepExecutor = (*AgentExecutor)(nil)

func (e *AgentExecutor) Execute(ctx context.Context, step pipeline.StepDef, runID int64, env map[string]string) error {
	job := Job{
		RunID:    runID,
		StepID:   step.ID,
		Image:    step.Image,
		Commands: step.Commands,
		Env:      env,
		TimeoutS: step.Timeout,
		// P7④: docker_build fields (Image already holds the expanded target ref)
		StepType:   step.Type,
		Dockerfile: step.Dockerfile,
		Context:    step.BuildContext,
		Push:       step.Push,
	}
	done := e.D.Enqueue(job)
	select {
	case <-ctx.Done():
		e.D.Drop(runID, step.ID)
		return ctx.Err()
	case res, ok := <-done:
		if !ok {
			// Dropped (run canceled / step timeout before claim).
			return ctx.Err()
		}
		if res.ok {
			return nil
		}
		if res.message == "" {
			return errors.New("agent reported step failure")
		}
		return errors.New(res.message)
	}
}
