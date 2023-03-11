package watch

import (
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	"github.com/leg100/otf"
	"github.com/leg100/otf/json"
	"github.com/leg100/otf/run"
	"github.com/r3labs/sse/v2"
	"github.com/stretchr/testify/assert"
)

func TestAPI(t *testing.T) {
	// input event channel
	in := make(chan otf.Event, 1)
	// output event channel
	out := make(chan *sse.Event)

	// inject input event
	in <- otf.Event{
		Payload: &run.Run{},
		Type:    otf.EventRunCreated,
	}
	// expected output event
	want := &sse.Event{
		Data:  json.MustMarshal(&run.Run{}),
		Event: []byte("run_created"),
	}

	srv := &api{
		svc:          &fakeApp{ch: in},
		Logger:       logr.Discard(),
		eventsServer: &fakeEventsServer{published: out},
	}

	r := httptest.NewRequest("", "/", nil)
	w := httptest.NewRecorder()
	srv.watch(w, r)

	assert.Equal(t, want, <-out)
}
