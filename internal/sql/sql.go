// Package sql implements persistent storage using the postgres database.
package sql

//go:generate go run generate_types.go

import (
	"time"

	"github.com/pkg/errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/leg100/otf/internal"
)

// Bool converts a go-boolean into a postgres non-null boolean
func Bool(b bool) pgtype.Bool {
	return pgtype.Bool{Bool: b, Valid: true}
}

// BoolPtr converts a go-boolean pointer into a postgres nullable boolean
func BoolPtr(s *bool) pgtype.Bool {
	if s != nil {
		return pgtype.Bool{Bool: *s, Valid: true}
	}
	return pgtype.Bool{}
}

// String converts a go-string into a postgres non-null string
func String(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: true}
}

// StringPtr converts a go-string pointer into a postgres nullable string
func StringPtr(s *string) pgtype.Text {
	if s != nil {
		return pgtype.Text{String: *s, Valid: true}
	}
	return pgtype.Text{}
}

// StringArray converts a go-string slice into a postgres text array
func StringArray(ss []string) []pgtype.Text {
	p := make([]pgtype.Text, len(ss))
	for i, s := range ss {
		p[i] = pgtype.Text{String: s, Valid: true}
	}
	return p
}

// FromStringArray converts a postgres text array into a go string slice.
func FromStringArray(pta []pgtype.Text) []string {
	ss := make([]string, len(pta))
	for i, t := range pta {
		ss[i] = t.String
	}
	return ss
}

// Int4 converts a go-int into a postgres non-null int4
func Int4(s int) pgtype.Int4 {
	return pgtype.Int4{Int32: int32(s), Valid: true}
}

// Int4Ptr converts a go-int pointer into a postgres nullable int4
func Int4Ptr(s *int) pgtype.Int4 {
	if s != nil {
		return pgtype.Int4{Int32: int32(*s), Valid: true}
	}
	return pgtype.Int4{}
}

// Int8 converts a go-int into a postgres non-null int8
func Int8(s int) pgtype.Int8 {
	return pgtype.Int8{Int64: int64(s), Valid: true}
}

// Int8Ptr converts a go-int pointer into a postgres nullable int8
func Int8Ptr(s *int) pgtype.Int8 {
	if s != nil {
		return pgtype.Int8{Int64: int64(*s), Valid: true}
	}
	return pgtype.Int8{}
}

// NullString returns a postgres null string
func NullString() pgtype.Text {
	return pgtype.Text{}
}

// UUID converts a google-go-uuid into a postgres non-null UUID
func UUID(s uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: s, Valid: true}
}

// Timestamptz converts a go-time into a postgres non-null timestamptz
func Timestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

// TimestamptzPtr converts a go-time pointer into a postgres nullable timestamptz
func TimestamptzPtr(t *time.Time) pgtype.Timestamptz {
	if t != nil {
		return pgtype.Timestamptz{Time: *t, Valid: true}
	}
	return pgtype.Timestamptz{}
}

func Error(err error) error {
	var pgErr *pgconn.PgError
	switch {
	case NoRowsInResultError(err):
		return internal.ErrResourceNotFound
	case errors.As(err, &pgErr):
		switch pgErr.Code {
		case "23503": // foreign key violation
			return &internal.ForeignKeyError{PgError: pgErr}
		case "23505": // unique violation
			return internal.ErrResourceAlreadyExists
		}
		fallthrough
	default:
		return err
	}
}

func NoRowsInResultError(err error) bool {
	for {
		err = errors.Unwrap(err)
		if err == nil {
			return false
		} else if err.Error() == "no rows in result set" {
			return true
		}
	}
}
