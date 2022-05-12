package app

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/leg100/otf"
)

var _ otf.ApplyService = (*ApplyService)(nil)

type ApplyService struct {
	db otf.RunStore

	logs otf.ChunkStore

	otf.EventService

	cache otf.Cache

	logr.Logger
}

func NewApplyService(db otf.RunStore, logs otf.ChunkStore, logger logr.Logger, es otf.EventService, cache otf.Cache) *ApplyService {
	return &ApplyService{
		db:           db,
		EventService: es,
		logs:         logs,
		cache:        cache,
		Logger:       logger,
	}
}

func (s ApplyService) Get(id string) (*otf.Apply, error) {
	run, err := s.db.Get(otf.RunGetOptions{ApplyID: &id})
	if err != nil {
		return nil, err
	}
	return run.Apply, nil
}

// GetChunk reads a chunk of logs for a terraform apply.
func (s ApplyService) GetChunk(ctx context.Context, id string, opts otf.GetChunkOptions) (otf.Chunk, error) {
	logs, err := s.logs.GetChunk(ctx, id, opts)
	if err != nil {
		s.Error(err, "reading apply logs", "id", id, "offset", opts.Offset, "limit", opts.Limit)
		return otf.Chunk{}, err
	}

	return logs, nil
}

// PutChunk writes a chunk of logs for a terraform apply.
func (s ApplyService) PutChunk(ctx context.Context, id string, chunk otf.Chunk) error {
	err := s.logs.PutChunk(ctx, id, chunk)
	if err != nil {
		s.Error(err, "writing apply logs", "id", id, "start", chunk.Start, "end", chunk.End)
		return err
	}

	if !chunk.End {
		return nil
	}

	// Last chunk uploaded. A summary of applied changes can now be parsed from
	// the full logs and set on the apply obj.
	chunk, err = s.logs.GetChunk(ctx, id, otf.GetChunkOptions{})
	if err != nil {
		s.Error(err, "reading apply logs", "id", id)
		return err
	}

	summary, err := otf.ParseApplyOutput(string(chunk.Data))
	if err != nil {
		s.Error(err, "summarising applied changes", "id", id)
		return err
	}

	if err := s.db.UpdateApplyResources(id, summary); err != nil {
		s.Error(err, "persisting summary of applied changes", "id", id)
		return err
	}

	return nil
}

// Start marks a apply as having started
func (s ApplyService) Start(ctx context.Context, runID string, opts otf.JobStartOptions) (*otf.Run, error) {
	run, err := s.db.UpdateStatus(runID, func(run *otf.Run) error {
		return run.Apply.Start(run)
	})
	if err != nil {
		s.Error(err, "starting apply")
		return nil, err
	}

	s.V(0).Info("started apply", "id", run.ID)

	return run, nil
}

// Finish marks a apply as having finished.  An event is emitted to notify any
// subscribers of the new state.
func (s ApplyService) Finish(ctx context.Context, runID string, opts otf.JobFinishOptions) (*otf.Run, error) {
	run, err := s.db.UpdateStatus(runID, func(run *otf.Run) (err error) {
		return run.Apply.Finish(run)
	})
	if err != nil {
		s.Error(err, "finishing apply", "id", runID)
		return nil, err
	}

	s.V(0).Info("finished apply", "id", runID)

	s.Publish(otf.Event{Payload: run, Type: otf.EventRunApplied})

	return run, nil
}
