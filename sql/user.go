package sql

import (
	"context"
	"fmt"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/leg100/otf"
)

var (
	_ otf.UserStore = (*UserDB)(nil)
)

type UserDB struct {
	*pgxpool.Pool
}

func NewUserDB(conn *pgxpool.Pool) *UserDB {
	return &UserDB{
		Pool: conn,
	}
}

// Create persists a User to the DB.
func (db UserDB) Create(ctx context.Context, user *otf.User) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	q := NewQuerier(tx)

	result, err := q.InsertUser(ctx, InsertUserParams{
		ID:                  user.ID,
		Username:            user.Username,
		CurrentOrganization: *user.CurrentOrganization,
	})
	if err != nil {
		return err
	}
	user.CreatedAt = result.CreatedAt
	user.UpdatedAt = result.UpdatedAt

	for _, org := range user.Organizations {
		_, err = q.InsertOrganizationMembership(ctx, user.ID, org.ID)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (db UserDB) SetCurrentOrganization(ctx context.Context, userID, orgName string) error {
	q := NewQuerier(db.Pool)

	_, err := q.UpdateUserCurrentOrganization(ctx, orgName, userID)
	return err
}

func (db UserDB) List(ctx context.Context) ([]*otf.User, error) {
	q := NewQuerier(db.Pool)

	result, err := q.FindUsers(ctx)
	if err != nil {
		return nil, err
	}

	return otf.UnmarshalUserListFromDB(result)
}

// Get retrieves a user from the DB, along with its sessions.
func (db UserDB) Get(ctx context.Context, spec otf.UserSpec) (*otf.User, error) {
	q := NewQuerier(db.Pool)

	if spec.UserID != nil {
		result, err := q.FindUserByID(ctx, *spec.UserID)
		if err != nil {
			return nil, err
		}
		return otf.UnmarshalUserFromDB(result)
	} else if spec.Username != nil {
		result, err := q.FindUserByUsername(ctx, *spec.Username)
		if err != nil {
			return nil, err
		}
		return otf.UnmarshalUserFromDB(result)
	} else if spec.AuthenticationToken != nil {
		result, err := q.FindUserByAuthenticationToken(ctx, *spec.AuthenticationToken)
		if err != nil {
			return nil, err
		}
		return otf.UnmarshalUserFromDB(result)
	} else if spec.AuthenticationTokenID != nil {
		result, err := q.FindUserByAuthenticationTokenID(ctx, *spec.AuthenticationTokenID)
		if err != nil {
			return nil, err
		}
		return otf.UnmarshalUserFromDB(result)
	} else if spec.SessionToken != nil {
		result, err := q.FindUserBySessionToken(ctx, *spec.SessionToken)
		if err != nil {
			return nil, err
		}
		return otf.UnmarshalUserFromDB(result)
	} else {
		return nil, fmt.Errorf("unsupported user spec for retrieving user")
	}
}

func (db UserDB) AddOrganizationMembership(ctx context.Context, id, orgID string) error {
	q := NewQuerier(db.Pool)

	_, err := q.InsertOrganizationMembership(ctx, id, orgID)
	return err
}

func (db UserDB) RemoveOrganizationMembership(ctx context.Context, id, orgID string) error {
	q := NewQuerier(db.Pool)

	result, err := q.DeleteOrganizationMembership(ctx, id, orgID)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return otf.ErrResourceNotFound
	}

	return nil
}

// Delete deletes a user from the DB.
func (db UserDB) Delete(ctx context.Context, spec otf.UserSpec) error {
	q := NewQuerier(db.Pool)

	var result pgconn.CommandTag
	var err error
	if spec.UserID != nil {
		result, err = q.DeleteUserByID(ctx, *spec.UserID)
	} else if spec.Username != nil {
		result, err = q.DeleteUserByUsername(ctx, *spec.Username)
	} else {
		return fmt.Errorf("unsupported user spec for deletion")
	}
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return otf.ErrResourceNotFound
	}

	return nil
}
