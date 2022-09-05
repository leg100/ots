package otf

import "context"

const (
	EventOrganizationCreated EventType = "organization_created"
	EventOrganizationDeleted EventType = "organization_deleted"
	EventWorkspaceCreated    EventType = "workspace_created"
	EventWorkspaceDeleted    EventType = "workspace_deleted"
	// EventLatestRunUpdate is an update to the "latest" run for a workspace
	EventLatestRunUpdate EventType = "run_latest_update"
	EventRunCreated      EventType = "run_created"
	EventRunStatusUpdate EventType = "run_status_update"
	EventRunDeleted      EventType = "run_deleted"
	EventRunCancel       EventType = "run_cancel"
	EventRunForceCancel  EventType = "run_force_cancel"
	EventError           EventType = "error"
)

// EventType identifies the type of event
type EventType string

// Event represents an event in the lifecycle of an oTF resource
type Event struct {
	Type    EventType
	Payload interface{}
}

// PubSubService provides low-level access to pub-sub behaviours. Access is
// unauthenticated.
type PubSubService interface {
	// Publish an event
	Publish(Event)
	// Subscribe creates a subscription to a stream of errors
	//
	// TODO: add context param and return channel instead of Subscription. The
	// caller is then expected to cancel the context instead of calling Close()
	// on Subscription. This seems like a cleaner solution with less cleanup
	// because the caller in many cases is having itself to handle a canceled
	// context from its parent caller and then call Close().
	Subscribe(id string) (Subscription, error)
}

// EventService allows interacting with events. Access is authenticated.
type EventService interface {
	// TODO: remove - this is not authenticated
	PubSubService
	// Watch provides access to a stream of events. The WatchOptions filters
	// events. The caller must ensure WatchOptions are specified in accordance
	// with their access, i.e. Watch is not clever enough to send all events the
	// caller is entitled to, instead the caller has to specify options to
	// ensure only events they are permitted to access are sent, otherwise Watch
	// will deny access.
	Watch(context.Context, WatchOptions) (<-chan Event, error)
}

// Subscription represents a stream of events for a subscriber
type Subscription interface {
	// Event stream for all subscriber's event.
	C() <-chan Event

	// Closes the event stream channel and disconnects from the event service.
	Close() error
}

// WatchOptions filter the events returned by the Watch endpoint. Either:
// (a) WorkspaceID must be specified
// (b) Both OrganizationName and WorkspaceName must be specified
// (c) None are specified
// These options are mutually exclusive.
type WatchOptions struct {
	// Filter by workspace ID
	WorkspaceID *string `schema:"workspace_id"`
	// Filter by organization name
	OrganizationName *string `schema:"organization_name"`
	// Filter by workspace name
	WorkspaceName *string `schema:"workspace_name"`
}
