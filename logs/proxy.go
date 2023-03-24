package logs

import (
	"context"
	"fmt"
	"reflect"

	"github.com/go-logr/logr"
	"github.com/leg100/otf"
)

type (
	// proxy is a caching proxy for log chunks
	proxy struct {
		cache otf.Cache
		db    db

		otf.PubSubService
		logr.Logger
	}

	db interface {
		GetLogs(ctx context.Context, runID string, phase otf.PhaseType) ([]byte, error)
		put(ctx context.Context, chunk otf.Chunk) (otf.Chunk, error)
	}
)

func newProxy(opts Options) *proxy {
	db := &pgdb{opts.DB}
	p := &proxy{
		Logger:        opts.Logger,
		PubSubService: opts.Broker,
		cache:         opts.Cache,
		db:            db,
	}

	// Register with broker so that it can relay log chunks
	opts.Register(reflect.TypeOf(otf.Chunk{}), db)

	return p
}

// Start chunk proxy daemon, which keeps the cache up-to-date with logs
// published on other nodes in the cluster
func (p *proxy) Start(ctx context.Context) error {
	ch := make(chan otf.Chunk)
	defer close(ch)

	// TODO: if it loses its connection to the stream it should keep retrying,
	// with a backoff alg, and it should invalidate the cache *entirely* because
	// it may have missed updates, potentially rendering the cache stale.
	sub, err := p.Subscribe(ctx, "chunk-proxy")
	if err != nil {
		return err
	}

	for {
		select {
		case event, ok := <-sub:
			if !ok {
				return nil
			}
			chunk, ok := event.Payload.(otf.Chunk)
			if !ok {
				// skip non-log events
				continue
			}
			if err := p.cacheChunk(ctx, chunk); err != nil {
				p.Error(err, "caching log chunk")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// GetChunk attempts to retrieve a chunk from the cache before falling back to
// using the backend store.
func (p *proxy) get(ctx context.Context, opts otf.GetChunkOptions) (otf.Chunk, error) {
	key := cacheKey(opts.RunID, opts.Phase)

	data, err := p.cache.Get(key)
	if err != nil {
		// fall back to retrieving from db...
		data, err = p.db.GetLogs(ctx, opts.RunID, opts.Phase)
		if err != nil {
			return otf.Chunk{}, err
		}
		// ...and cache it
		if err := p.cache.Set(key, data); err != nil {
			return otf.Chunk{}, err
		}
	}
	chunk := otf.Chunk{RunID: opts.RunID, Phase: opts.Phase, Data: data}
	// Cut chunk down to requested size.
	return chunk.Cut(opts), nil
}

// PutChunk writes a chunk of data to the backend store before caching it.
func (p *proxy) put(ctx context.Context, chunk otf.Chunk) error {
	persisted, err := p.db.put(ctx, chunk)
	if err != nil {
		return err
	}
	if err := p.cacheChunk(ctx, chunk); err != nil {
		return err
	}
	// publish chunk so that other otfd nodes can receive the chunk
	p.Publish(otf.Event{
		Type:    otf.EventLogChunk,
		Payload: persisted,
	})
	return nil
}

func (p *proxy) cacheChunk(ctx context.Context, chunk otf.Chunk) error {
	key := cacheKey(chunk.RunID, chunk.Phase)

	// first chunk: don't append
	if chunk.IsStart() {
		return p.cache.Set(key, chunk.Data)
	}
	// successive chunks: append
	if previous, err := p.cache.Get(key); err == nil {
		return p.cache.Set(key, append(previous, chunk.Data...))
	}
	// no cache entry; repopulate cache from db
	logs, err := p.db.GetLogs(ctx, chunk.RunID, chunk.Phase)
	if err != nil {
		return err
	}
	return p.cache.Set(key, logs)
}

// cacheKey generates a key for caching log chunks.
func cacheKey(runID string, phase otf.PhaseType) string {
	return fmt.Sprintf("%s.%s.log", runID, string(phase))
}
