package run

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/leg100/otf/internal"
	"github.com/leg100/otf/internal/resource"
	"golang.org/x/exp/maps"
)

// TimeoutLockID is a unique ID guaranteeing only one timeout daemon on a cluster is running at any time.
const TimeoutLockID int64 = 179366396344335598

// By default check timed out runs every minute
var defaultCheckInterval = time.Minute

type (
	// Timeout is a daemon that "times out" runs if one of the phases -
	// planning, applying - exceeds a timeout. This can happen for a number of
	// reasons, for example a terraform plan or apply is stuck talking to an
	// unresponsive API, or if OTF itself has terminated ungracefully and left
	// runs in a planning or applying state.
	Timeout struct {
		logr.Logger

		OverrideCheckInterval time.Duration
		PlanningTimeout       time.Duration
		ApplyingTimeout       time.Duration
		Runs                  timeoutRunClient
	}

	timeoutRunClient interface {
		List(ctx context.Context, opts ListOptions) (*resource.Page[*Run], error)
		Cancel(ctx context.Context, runID string) error
	}
)

// Start the timeout daemon.
func (e *Timeout) Start(ctx context.Context) error {
	// Set the interval between checking for timed out runs. Unless an override
	// interval has been provided, use a default.
	interval := defaultCheckInterval
	if e.OverrideCheckInterval != 0 {
		interval = e.OverrideCheckInterval
	}

	ticker := time.NewTicker(interval)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			e.check(ctx)
		}
	}
}

func (e *Timeout) check(ctx context.Context) {
	// Statuses that are checked for timeout
	statuses := map[Status]struct {
		// run phase corresponding to phase
		phase   internal.PhaseType
		timeout time.Duration
	}{
		RunPlanning: {
			phase:   internal.PlanPhase,
			timeout: e.PlanningTimeout,
		},
		RunApplying: {
			phase:   internal.ApplyPhase,
			timeout: e.ApplyingTimeout,
		},
	}
	// Retrieve all runs with the given statuses
	runs, err := resource.ListAll(func(opts resource.PageOptions) (*resource.Page[*Run], error) {
		return e.Runs.List(ctx, ListOptions{
			Statuses:    maps.Keys(statuses),
			PageOptions: opts,
		})
	})
	if err != nil {
		e.Error(err, "checking run status timeouts")
		return
	}
	for _, run := range runs {
		s, ok := statuses[run.Status]
		if !ok {
			// Should never happen.
			continue
		}
		// For each run retrieve the timestamp for when it started
		// the status
		started, err := run.StatusTimestamp(run.Status)
		if err != nil {
			// should never happen
			e.Error(err, "checking run timeout", "run_id", run.ID, "status", run.Status)
			continue
		}
		// Check whether the timeout has been exceeded
		if time.Since(started) > s.timeout {
			// Timeout exceeded...
			//
			// Inform the user via log message,
			e.Error(nil, "run timeout exceeded",
				fmt.Sprintf("%s_timeout", run.Status), s.timeout,
				fmt.Sprintf("started_%s", run.Status), started,
				"run_id", run.ID,
				"status", run.Status,
			)
			// Send cancellation signal to terminate terraform process and force
			// run into the canceled state.
			//
			// TODO: bubble up to the UI/API the reason for cancelling the run.
			_ = e.Runs.Cancel(ctx, run.ID)
		}
	}
}
