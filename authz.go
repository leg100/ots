package otf

import (
	"context"
	"errors"
	"fmt"
)

// unexported key type prevents collisions
type subjectCtxKeyType string

const subjectCtxKey subjectCtxKeyType = "subject"

var (
	ErrAccessNotPermitted = errors.New("access to the resource is not permitted")
)

// AddSubjectToContext adds a subject to a context
func AddSubjectToContext(ctx context.Context, subj Subject) context.Context {
	return context.WithValue(ctx, subjectCtxKey, subj)
}

// SubjectFromContext retrieves a subject from a context
func SubjectFromContext(ctx context.Context) (Subject, error) {
	subj, ok := ctx.Value(subjectCtxKey).(Subject)
	if !ok {
		return nil, fmt.Errorf("no subject in context")
	}
	return subj, nil
}

// UserFromContext retrieves a user from a context
func UserFromContext(ctx context.Context) (*User, error) {
	subj, ok := ctx.Value(subjectCtxKey).(Subject)
	if !ok {
		return nil, fmt.Errorf("no subject in context")
	}
	user, ok := subj.(*User)
	if !ok {
		return nil, fmt.Errorf("subject found in context but it is not a user")
	}
	return user, nil
}

// Subject is an entity attempting to carry out an action on a resource.
type Subject interface {
	// CanAccess determines if the subject is allowed to access the resource.
	CanAccess(Resource) bool
}

// Resource is an identifable otf resource to which a subject can be permitted
// to invoke actions on.
type Resource interface {
	// OrganizationID is the id of the organization the resource belongs to.
	// Every resource belongs to an organization (or *is* an organization).
	OrganizationID() string
}

// CanAccess is a convenience function that extracts a subject from the context
// and checks whether it is allowed to access the resource.
func CanAccess(ctx context.Context, res Resource) bool {
	subj, err := SubjectFromContext(ctx)
	if err != nil {
		return false
	}
	return subj.CanAccess(res)
}
