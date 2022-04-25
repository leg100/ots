// Code generated by pggen. DO NOT EDIT.

package db

import (
	"context"
	"fmt"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
)

// Querier is a typesafe Go interface backed by SQL queries.
//
// Methods ending with Batch enqueue a query to run later in a pgx.Batch. After
// calling SendBatch on pgx.Conn, pgxpool.Pool, or pgx.Tx, use the Scan methods
// to parse the results.
type Querier interface {
	// FindOrganizationByName finds an organization by name.
	// 
	FindOrganizationByName(ctx context.Context, name string) (FindOrganizationByNameRow, error)
	// FindOrganizationByNameBatch enqueues a FindOrganizationByName query into batch to be executed
	// later by the batch.
	FindOrganizationByNameBatch(batch genericBatch, name string)
	// FindOrganizationByNameScan scans the result of an executed FindOrganizationByNameBatch query.
	FindOrganizationByNameScan(results pgx.BatchResults) (FindOrganizationByNameRow, error)

	// InsertOrganization inserts an organization and returns the entire row.
	// 
	InsertOrganization(ctx context.Context, params InsertOrganizationParams) (InsertOrganizationRow, error)
	// InsertOrganizationBatch enqueues a InsertOrganization query into batch to be executed
	// later by the batch.
	InsertOrganizationBatch(batch genericBatch, params InsertOrganizationParams)
	// InsertOrganizationScan scans the result of an executed InsertOrganizationBatch query.
	InsertOrganizationScan(results pgx.BatchResults) (InsertOrganizationRow, error)

	// UpdateOrganizationNameByName updates an organization with a new name,
	// identifying the organization with its existing name, and returns the
	// updated row.
	// 
	UpdateOrganizationNameByName(ctx context.Context, newName string, name string) (UpdateOrganizationNameByNameRow, error)
	// UpdateOrganizationNameByNameBatch enqueues a UpdateOrganizationNameByName query into batch to be executed
	// later by the batch.
	UpdateOrganizationNameByNameBatch(batch genericBatch, newName string, name string)
	// UpdateOrganizationNameByNameScan scans the result of an executed UpdateOrganizationNameByNameBatch query.
	UpdateOrganizationNameByNameScan(results pgx.BatchResults) (UpdateOrganizationNameByNameRow, error)

	// DeleteOrganization deletes an organization by id.
	// 
	DeleteOrganization(ctx context.Context, name string) (pgconn.CommandTag, error)
	// DeleteOrganizationBatch enqueues a DeleteOrganization query into batch to be executed
	// later by the batch.
	DeleteOrganizationBatch(batch genericBatch, name string)
	// DeleteOrganizationScan scans the result of an executed DeleteOrganizationBatch query.
	DeleteOrganizationScan(results pgx.BatchResults) (pgconn.CommandTag, error)

	// FindWorkspaceByName finds a workspace by name and organization name.
	// 
	FindWorkspaceByName(ctx context.Context, name string, organizationName string) (FindWorkspaceByNameRow, error)
	// FindWorkspaceByNameBatch enqueues a FindWorkspaceByName query into batch to be executed
	// later by the batch.
	FindWorkspaceByNameBatch(batch genericBatch, name string, organizationName string)
	// FindWorkspaceByNameScan scans the result of an executed FindWorkspaceByNameBatch query.
	FindWorkspaceByNameScan(results pgx.BatchResults) (FindWorkspaceByNameRow, error)

	// FindWorkspaceByID finds a workspace by id.
	// 
	FindWorkspaceByID(ctx context.Context, id string) (FindWorkspaceByIDRow, error)
	// FindWorkspaceByIDBatch enqueues a FindWorkspaceByID query into batch to be executed
	// later by the batch.
	FindWorkspaceByIDBatch(batch genericBatch, id string)
	// FindWorkspaceByIDScan scans the result of an executed FindWorkspaceByIDBatch query.
	FindWorkspaceByIDScan(results pgx.BatchResults) (FindWorkspaceByIDRow, error)

	// DeleteWorkspaceByID deletes a workspace by id.
	// 
	DeleteWorkspaceByID(ctx context.Context, workspaceID string) (pgconn.CommandTag, error)
	// DeleteWorkspaceByIDBatch enqueues a DeleteWorkspaceByID query into batch to be executed
	// later by the batch.
	DeleteWorkspaceByIDBatch(batch genericBatch, workspaceID string)
	// DeleteWorkspaceByIDScan scans the result of an executed DeleteWorkspaceByIDBatch query.
	DeleteWorkspaceByIDScan(results pgx.BatchResults) (pgconn.CommandTag, error)

	// DeleteWorkspaceByName deletes a workspace by name and organization name.
	// 
	DeleteWorkspaceByName(ctx context.Context, name string, organizationName string) (pgconn.CommandTag, error)
	// DeleteWorkspaceByNameBatch enqueues a DeleteWorkspaceByName query into batch to be executed
	// later by the batch.
	DeleteWorkspaceByNameBatch(batch genericBatch, name string, organizationName string)
	// DeleteWorkspaceByNameScan scans the result of an executed DeleteWorkspaceByNameBatch query.
	DeleteWorkspaceByNameScan(results pgx.BatchResults) (pgconn.CommandTag, error)
}

type DBQuerier struct {
	conn  genericConn   // underlying Postgres transport to use
	types *typeResolver // resolve types by name
}

var _ Querier = &DBQuerier{}

// genericConn is a connection to a Postgres database. This is usually backed by
// *pgx.Conn, pgx.Tx, or *pgxpool.Pool.
type genericConn interface {
	// Query executes sql with args. If there is an error the returned Rows will
	// be returned in an error state. So it is allowed to ignore the error
	// returned from Query and handle it in Rows.
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)

	// QueryRow is a convenience wrapper over Query. Any error that occurs while
	// querying is deferred until calling Scan on the returned Row. That Row will
	// error with pgx.ErrNoRows if no rows are returned.
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row

	// Exec executes sql. sql can be either a prepared statement name or an SQL
	// string. arguments should be referenced positionally from the sql string
	// as $1, $2, etc.
	Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error)
}

// genericBatch batches queries to send in a single network request to a
// Postgres server. This is usually backed by *pgx.Batch.
type genericBatch interface {
	// Queue queues a query to batch b. query can be an SQL query or the name of a
	// prepared statement. See Queue on *pgx.Batch.
	Queue(query string, arguments ...interface{})
}

// NewQuerier creates a DBQuerier that implements Querier. conn is typically
// *pgx.Conn, pgx.Tx, or *pgxpool.Pool.
func NewQuerier(conn genericConn) *DBQuerier {
	return NewQuerierConfig(conn, QuerierConfig{})
}

type QuerierConfig struct {
	// DataTypes contains pgtype.Value to use for encoding and decoding instead
	// of pggen-generated pgtype.ValueTranscoder.
	//
	// If OIDs are available for an input parameter type and all of its
	// transitive dependencies, pggen will use the binary encoding format for
	// the input parameter.
	DataTypes []pgtype.DataType
}

// NewQuerierConfig creates a DBQuerier that implements Querier with the given
// config. conn is typically *pgx.Conn, pgx.Tx, or *pgxpool.Pool.
func NewQuerierConfig(conn genericConn, cfg QuerierConfig) *DBQuerier {
	return &DBQuerier{conn: conn, types: newTypeResolver(cfg.DataTypes)}
}

// WithTx creates a new DBQuerier that uses the transaction to run all queries.
func (q *DBQuerier) WithTx(tx pgx.Tx) (*DBQuerier, error) {
	return &DBQuerier{conn: tx}, nil
}

// preparer is any Postgres connection transport that provides a way to prepare
// a statement, most commonly *pgx.Conn.
type preparer interface {
	Prepare(ctx context.Context, name, sql string) (sd *pgconn.StatementDescription, err error)
}

// PrepareAllQueries executes a PREPARE statement for all pggen generated SQL
// queries in querier files. Typical usage is as the AfterConnect callback
// for pgxpool.Config
//
// pgx will use the prepared statement if available. Calling PrepareAllQueries
// is an optional optimization to avoid a network round-trip the first time pgx
// runs a query if pgx statement caching is enabled.
func PrepareAllQueries(ctx context.Context, p preparer) error {
	if _, err := p.Prepare(ctx, findOrganizationByNameSQL, findOrganizationByNameSQL); err != nil {
		return fmt.Errorf("prepare query 'FindOrganizationByName': %w", err)
	}
	if _, err := p.Prepare(ctx, insertOrganizationSQL, insertOrganizationSQL); err != nil {
		return fmt.Errorf("prepare query 'InsertOrganization': %w", err)
	}
	if _, err := p.Prepare(ctx, updateOrganizationNameByNameSQL, updateOrganizationNameByNameSQL); err != nil {
		return fmt.Errorf("prepare query 'UpdateOrganizationNameByName': %w", err)
	}
	if _, err := p.Prepare(ctx, deleteOrganizationSQL, deleteOrganizationSQL); err != nil {
		return fmt.Errorf("prepare query 'DeleteOrganization': %w", err)
	}
	if _, err := p.Prepare(ctx, findWorkspaceByNameSQL, findWorkspaceByNameSQL); err != nil {
		return fmt.Errorf("prepare query 'FindWorkspaceByName': %w", err)
	}
	if _, err := p.Prepare(ctx, findWorkspaceByIDSQL, findWorkspaceByIDSQL); err != nil {
		return fmt.Errorf("prepare query 'FindWorkspaceByID': %w", err)
	}
	if _, err := p.Prepare(ctx, deleteWorkspaceByIDSQL, deleteWorkspaceByIDSQL); err != nil {
		return fmt.Errorf("prepare query 'DeleteWorkspaceByID': %w", err)
	}
	if _, err := p.Prepare(ctx, deleteWorkspaceByNameSQL, deleteWorkspaceByNameSQL); err != nil {
		return fmt.Errorf("prepare query 'DeleteWorkspaceByName': %w", err)
	}
	return nil
}

// Organizations represents the Postgres composite type "organizations".
type Organizations struct {
	OrganizationID  *string            `json:"organization_id"`
	CreatedAt       pgtype.Timestamptz `json:"created_at"`
	UpdatedAt       pgtype.Timestamptz `json:"updated_at"`
	Name            *string            `json:"name"`
	SessionRemember *int32             `json:"session_remember"`
	SessionTimeout  *int32             `json:"session_timeout"`
}

// typeResolver looks up the pgtype.ValueTranscoder by Postgres type name.
type typeResolver struct {
	connInfo *pgtype.ConnInfo // types by Postgres type name
}

func newTypeResolver(types []pgtype.DataType) *typeResolver {
	ci := pgtype.NewConnInfo()
	for _, typ := range types {
		if txt, ok := typ.Value.(textPreferrer); ok && typ.OID != unknownOID {
			typ.Value = txt.ValueTranscoder
		}
		ci.RegisterDataType(typ)
	}
	return &typeResolver{connInfo: ci}
}

// findValue find the OID, and pgtype.ValueTranscoder for a Postgres type name.
func (tr *typeResolver) findValue(name string) (uint32, pgtype.ValueTranscoder, bool) {
	typ, ok := tr.connInfo.DataTypeForName(name)
	if !ok {
		return 0, nil, false
	}
	v := pgtype.NewValue(typ.Value)
	return typ.OID, v.(pgtype.ValueTranscoder), true
}

// setValue sets the value of a ValueTranscoder to a value that should always
// work and panics if it fails.
func (tr *typeResolver) setValue(vt pgtype.ValueTranscoder, val interface{}) pgtype.ValueTranscoder {
	if err := vt.Set(val); err != nil {
		panic(fmt.Sprintf("set ValueTranscoder %T to %+v: %s", vt, val, err))
	}
	return vt
}

type compositeField struct {
	name       string                 // name of the field
	typeName   string                 // Postgres type name
	defaultVal pgtype.ValueTranscoder // default value to use
}

func (tr *typeResolver) newCompositeValue(name string, fields ...compositeField) pgtype.ValueTranscoder {
	if _, val, ok := tr.findValue(name); ok {
		return val
	}
	fs := make([]pgtype.CompositeTypeField, len(fields))
	vals := make([]pgtype.ValueTranscoder, len(fields))
	isBinaryOk := true
	for i, field := range fields {
		oid, val, ok := tr.findValue(field.typeName)
		if !ok {
			oid = unknownOID
			val = field.defaultVal
		}
		isBinaryOk = isBinaryOk && oid != unknownOID
		fs[i] = pgtype.CompositeTypeField{Name: field.name, OID: oid}
		vals[i] = val
	}
	// Okay to ignore error because it's only thrown when the number of field
	// names does not equal the number of ValueTranscoders.
	typ, _ := pgtype.NewCompositeTypeValues(name, fs, vals)
	if !isBinaryOk {
		return textPreferrer{typ, name}
	}
	return typ
}

func (tr *typeResolver) newArrayValue(name, elemName string, defaultVal func() pgtype.ValueTranscoder) pgtype.ValueTranscoder {
	if _, val, ok := tr.findValue(name); ok {
		return val
	}
	elemOID, elemVal, ok := tr.findValue(elemName)
	elemValFunc := func() pgtype.ValueTranscoder {
		return pgtype.NewValue(elemVal).(pgtype.ValueTranscoder)
	}
	if !ok {
		elemOID = unknownOID
		elemValFunc = defaultVal
	}
	typ := pgtype.NewArrayType(name, elemOID, elemValFunc)
	if elemOID == unknownOID {
		return textPreferrer{typ, name}
	}
	return typ
}

// newOrganizations creates a new pgtype.ValueTranscoder for the Postgres
// composite type 'organizations'.
func (tr *typeResolver) newOrganizations() pgtype.ValueTranscoder {
	return tr.newCompositeValue(
		"organizations",
		compositeField{"organization_id", "text", &pgtype.Text{}},
		compositeField{"created_at", "timestamptz", &pgtype.Timestamptz{}},
		compositeField{"updated_at", "timestamptz", &pgtype.Timestamptz{}},
		compositeField{"name", "text", &pgtype.Text{}},
		compositeField{"session_remember", "int4", &pgtype.Int4{}},
		compositeField{"session_timeout", "int4", &pgtype.Int4{}},
	)
}

const findOrganizationByNameSQL = `SELECT * FROM organizations WHERE name = $1;`

type FindOrganizationByNameRow struct {
	OrganizationID  string             `json:"organization_id"`
	CreatedAt       pgtype.Timestamptz `json:"created_at"`
	UpdatedAt       pgtype.Timestamptz `json:"updated_at"`
	Name            string             `json:"name"`
	SessionRemember *int32             `json:"session_remember"`
	SessionTimeout  *int32             `json:"session_timeout"`
}

// FindOrganizationByName implements Querier.FindOrganizationByName.
func (q *DBQuerier) FindOrganizationByName(ctx context.Context, name string) (FindOrganizationByNameRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "FindOrganizationByName")
	row := q.conn.QueryRow(ctx, findOrganizationByNameSQL, name)
	var item FindOrganizationByNameRow
	if err := row.Scan(&item.OrganizationID, &item.CreatedAt, &item.UpdatedAt, &item.Name, &item.SessionRemember, &item.SessionTimeout); err != nil {
		return item, fmt.Errorf("query FindOrganizationByName: %w", err)
	}
	return item, nil
}

// FindOrganizationByNameBatch implements Querier.FindOrganizationByNameBatch.
func (q *DBQuerier) FindOrganizationByNameBatch(batch genericBatch, name string) {
	batch.Queue(findOrganizationByNameSQL, name)
}

// FindOrganizationByNameScan implements Querier.FindOrganizationByNameScan.
func (q *DBQuerier) FindOrganizationByNameScan(results pgx.BatchResults) (FindOrganizationByNameRow, error) {
	row := results.QueryRow()
	var item FindOrganizationByNameRow
	if err := row.Scan(&item.OrganizationID, &item.CreatedAt, &item.UpdatedAt, &item.Name, &item.SessionRemember, &item.SessionTimeout); err != nil {
		return item, fmt.Errorf("scan FindOrganizationByNameBatch row: %w", err)
	}
	return item, nil
}

const insertOrganizationSQL = `INSERT INTO organizations (
    organization_id,
    created_at,
    updated_at,
    name,
    session_remember,
    session_timeout
) VALUES (
    $1,
    NOW(),
    NOW(),
    $2,
    $3,
    $4
)
RETURNING *;`

type InsertOrganizationParams struct {
	ID              string
	Name            string
	SessionRemember int32
	SessionTimeout  int32
}

type InsertOrganizationRow struct {
	OrganizationID  string             `json:"organization_id"`
	CreatedAt       pgtype.Timestamptz `json:"created_at"`
	UpdatedAt       pgtype.Timestamptz `json:"updated_at"`
	Name            string             `json:"name"`
	SessionRemember *int32             `json:"session_remember"`
	SessionTimeout  *int32             `json:"session_timeout"`
}

// InsertOrganization implements Querier.InsertOrganization.
func (q *DBQuerier) InsertOrganization(ctx context.Context, params InsertOrganizationParams) (InsertOrganizationRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "InsertOrganization")
	row := q.conn.QueryRow(ctx, insertOrganizationSQL, params.ID, params.Name, params.SessionRemember, params.SessionTimeout)
	var item InsertOrganizationRow
	if err := row.Scan(&item.OrganizationID, &item.CreatedAt, &item.UpdatedAt, &item.Name, &item.SessionRemember, &item.SessionTimeout); err != nil {
		return item, fmt.Errorf("query InsertOrganization: %w", err)
	}
	return item, nil
}

// InsertOrganizationBatch implements Querier.InsertOrganizationBatch.
func (q *DBQuerier) InsertOrganizationBatch(batch genericBatch, params InsertOrganizationParams) {
	batch.Queue(insertOrganizationSQL, params.ID, params.Name, params.SessionRemember, params.SessionTimeout)
}

// InsertOrganizationScan implements Querier.InsertOrganizationScan.
func (q *DBQuerier) InsertOrganizationScan(results pgx.BatchResults) (InsertOrganizationRow, error) {
	row := results.QueryRow()
	var item InsertOrganizationRow
	if err := row.Scan(&item.OrganizationID, &item.CreatedAt, &item.UpdatedAt, &item.Name, &item.SessionRemember, &item.SessionTimeout); err != nil {
		return item, fmt.Errorf("scan InsertOrganizationBatch row: %w", err)
	}
	return item, nil
}

const updateOrganizationNameByNameSQL = `UPDATE organizations
SET
    name = $1,
    updated_at = NOW()
WHERE name = $2
RETURNING *;`

type UpdateOrganizationNameByNameRow struct {
	OrganizationID  string             `json:"organization_id"`
	CreatedAt       pgtype.Timestamptz `json:"created_at"`
	UpdatedAt       pgtype.Timestamptz `json:"updated_at"`
	Name            string             `json:"name"`
	SessionRemember *int32             `json:"session_remember"`
	SessionTimeout  *int32             `json:"session_timeout"`
}

// UpdateOrganizationNameByName implements Querier.UpdateOrganizationNameByName.
func (q *DBQuerier) UpdateOrganizationNameByName(ctx context.Context, newName string, name string) (UpdateOrganizationNameByNameRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "UpdateOrganizationNameByName")
	row := q.conn.QueryRow(ctx, updateOrganizationNameByNameSQL, newName, name)
	var item UpdateOrganizationNameByNameRow
	if err := row.Scan(&item.OrganizationID, &item.CreatedAt, &item.UpdatedAt, &item.Name, &item.SessionRemember, &item.SessionTimeout); err != nil {
		return item, fmt.Errorf("query UpdateOrganizationNameByName: %w", err)
	}
	return item, nil
}

// UpdateOrganizationNameByNameBatch implements Querier.UpdateOrganizationNameByNameBatch.
func (q *DBQuerier) UpdateOrganizationNameByNameBatch(batch genericBatch, newName string, name string) {
	batch.Queue(updateOrganizationNameByNameSQL, newName, name)
}

// UpdateOrganizationNameByNameScan implements Querier.UpdateOrganizationNameByNameScan.
func (q *DBQuerier) UpdateOrganizationNameByNameScan(results pgx.BatchResults) (UpdateOrganizationNameByNameRow, error) {
	row := results.QueryRow()
	var item UpdateOrganizationNameByNameRow
	if err := row.Scan(&item.OrganizationID, &item.CreatedAt, &item.UpdatedAt, &item.Name, &item.SessionRemember, &item.SessionTimeout); err != nil {
		return item, fmt.Errorf("scan UpdateOrganizationNameByNameBatch row: %w", err)
	}
	return item, nil
}

const deleteOrganizationSQL = `DELETE
FROM organizations
WHERE name = $1;`

// DeleteOrganization implements Querier.DeleteOrganization.
func (q *DBQuerier) DeleteOrganization(ctx context.Context, name string) (pgconn.CommandTag, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "DeleteOrganization")
	cmdTag, err := q.conn.Exec(ctx, deleteOrganizationSQL, name)
	if err != nil {
		return cmdTag, fmt.Errorf("exec query DeleteOrganization: %w", err)
	}
	return cmdTag, err
}

// DeleteOrganizationBatch implements Querier.DeleteOrganizationBatch.
func (q *DBQuerier) DeleteOrganizationBatch(batch genericBatch, name string) {
	batch.Queue(deleteOrganizationSQL, name)
}

// DeleteOrganizationScan implements Querier.DeleteOrganizationScan.
func (q *DBQuerier) DeleteOrganizationScan(results pgx.BatchResults) (pgconn.CommandTag, error) {
	cmdTag, err := results.Exec()
	if err != nil {
		return cmdTag, fmt.Errorf("exec DeleteOrganizationBatch: %w", err)
	}
	return cmdTag, err
}

// textPreferrer wraps a pgtype.ValueTranscoder and sets the preferred encoding
// format to text instead binary (the default). pggen uses the text format
// when the OID is unknownOID because the binary format requires the OID.
// Typically occurs if the results from QueryAllDataTypes aren't passed to
// NewQuerierConfig.
type textPreferrer struct {
	pgtype.ValueTranscoder
	typeName string
}

// PreferredParamFormat implements pgtype.ParamFormatPreferrer.
func (t textPreferrer) PreferredParamFormat() int16 { return pgtype.TextFormatCode }

func (t textPreferrer) NewTypeValue() pgtype.Value {
	return textPreferrer{pgtype.NewValue(t.ValueTranscoder).(pgtype.ValueTranscoder), t.typeName}
}

func (t textPreferrer) TypeName() string {
	return t.typeName
}

// unknownOID means we don't know the OID for a type. This is okay for decoding
// because pgx call DecodeText or DecodeBinary without requiring the OID. For
// encoding parameters, pggen uses textPreferrer if the OID is unknown.
const unknownOID = 0
