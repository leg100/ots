package otf

import (
	"context"
	"fmt"
	"time"
)

const (
	DefaultAutoQueueRuns       = true
	DefaultConfigurationSource = "tfe-api"

	// List all available configuration version statuses.
	ConfigurationErrored  ConfigurationStatus = "errored"
	ConfigurationPending  ConfigurationStatus = "pending"
	ConfigurationUploaded ConfigurationStatus = "uploaded"
	// Default maximum config size is 10mb.
	DefaultConfigMaxSize int64 = 1024 * 1024 * 10
)

// ConfigurationVersion is a representation of an uploaded or ingressed
// Terraform configuration in  A workspace must have at least one configuration
// version before any runs may be queued on it.
type ConfigurationVersion struct {
	id                string
	createdAt         time.Time
	autoQueueRuns     bool
	source            ConfigurationSource
	speculative       bool
	status            ConfigurationStatus
	statusTimestamps  []ConfigurationVersionStatusTimestamp
	workspaceID       string
	ingressAttributes *IngressAttributes
}

func (cv *ConfigurationVersion) ID() string                  { return cv.id }
func (cv *ConfigurationVersion) CreatedAt() time.Time        { return cv.createdAt }
func (cv *ConfigurationVersion) String() string              { return cv.id }
func (cv *ConfigurationVersion) AutoQueueRuns() bool         { return cv.autoQueueRuns }
func (cv *ConfigurationVersion) Source() ConfigurationSource { return cv.source }
func (cv *ConfigurationVersion) Speculative() bool           { return cv.speculative }
func (cv *ConfigurationVersion) Status() ConfigurationStatus { return cv.status }
func (cv *ConfigurationVersion) StatusTimestamps() []ConfigurationVersionStatusTimestamp {
	return cv.statusTimestamps
}
func (cv *ConfigurationVersion) IngressAttributes() *IngressAttributes { return cv.ingressAttributes }

func (cv *ConfigurationVersion) StatusTimestamp(status ConfigurationStatus) (time.Time, error) {
	for _, sts := range cv.statusTimestamps {
		if sts.Status == status {
			return sts.Timestamp, nil
		}
	}
	return time.Time{}, ErrStatusTimestampNotFound
}

func (cv *ConfigurationVersion) WorkspaceID() string { return cv.workspaceID }

func (cv *ConfigurationVersion) AddStatusTimestamp(status ConfigurationStatus, timestamp time.Time) {
	cv.statusTimestamps = append(cv.statusTimestamps, ConfigurationVersionStatusTimestamp{
		Status:    status,
		Timestamp: timestamp,
	})
}

// Upload saves the config to the db and updates status accordingly.
func (cv *ConfigurationVersion) Upload(ctx context.Context, config []byte, uploader ConfigUploader) error {
	if cv.status != ConfigurationPending {
		return fmt.Errorf("cannot upload config for a configuration version with non-pending status: %s", cv.status)
	}

	// check config untars successfully and set errored status if not

	// upload config and set status depending on success
	status, err := uploader.Upload(ctx, config)
	if err != nil {
		return err
	}
	cv.status = status

	return nil
}

func (cv *ConfigurationVersion) updateStatus(status ConfigurationStatus) {
	cv.status = status
	cv.statusTimestamps = append(cv.statusTimestamps, ConfigurationVersionStatusTimestamp{
		Status:    status,
		Timestamp: CurrentTimestamp(),
	})
}

// ConfigurationStatus represents a configuration version status.
type ConfigurationStatus string

// ConfigurationVersionList represents a list of configuration versions.
type ConfigurationVersionList struct {
	*Pagination
	Items []*ConfigurationVersion
}

// ConfigurationSource represents a source of a configuration version.
type ConfigurationSource string

type ConfigurationVersionStatusTimestamp struct {
	Status    ConfigurationStatus
	Timestamp time.Time
}

// ConfigurationVersionCreateOptions represents the options for creating a
// configuration version. See jsonapi.ConfigurationVersionCreateOptions for more
// details.
type ConfigurationVersionCreateOptions struct {
	AutoQueueRuns *bool
	Speculative   *bool
	*IngressAttributes
}

type IngressAttributes struct {
	// ID     string
	Branch string
	// CloneURL          string
	// CommitMessage     string
	CommitSHA string
	// CommitURL         string
	// CompareURL        string
	Identifier      string
	IsPullRequest   bool
	OnDefaultBranch bool
	// PullRequestNumber int
	// PullRequestURL    string
	// PullRequestTitle  string
	// PullRequestBody   string
	// Tag               string
	// SenderUsername    string
	// SenderAvatarURL   string
	// SenderHTMLURL     string
}

type ConfigurationVersionService interface {
	CreateConfigurationVersion(ctx context.Context, workspaceID string, opts ConfigurationVersionCreateOptions) (*ConfigurationVersion, error)
	// CloneConfigurationVersion creates a new configuration version using the
	// config tarball of an existing configuration version.
	CloneConfigurationVersion(ctx context.Context, cvID string, opts ConfigurationVersionCreateOptions) (*ConfigurationVersion, error)
	GetConfigurationVersion(ctx context.Context, id string) (*ConfigurationVersion, error)
	GetLatestConfigurationVersion(ctx context.Context, workspaceID string) (*ConfigurationVersion, error)
	ListConfigurationVersions(ctx context.Context, workspaceID string, opts ConfigurationVersionListOptions) (*ConfigurationVersionList, error)

	// Upload handles verification and upload of the config tarball, updating
	// the config version upon success or failure.
	UploadConfig(ctx context.Context, id string, config []byte) error

	// Download retrieves the config tarball for the given config version ID.
	DownloadConfig(ctx context.Context, id string) ([]byte, error)
}

type ConfigurationVersionStore interface {
	// Creates a config version.
	CreateConfigurationVersion(ctx context.Context, cv *ConfigurationVersion) error
	// Get retrieves a config version.
	GetConfigurationVersion(ctx context.Context, opts ConfigurationVersionGetOptions) (*ConfigurationVersion, error)
	// GetConfig retrieves the config tarball for the given config version ID.
	GetConfig(ctx context.Context, id string) ([]byte, error)
	// List lists config versions for the given workspace.
	ListConfigurationVersions(ctx context.Context, workspaceID string, opts ConfigurationVersionListOptions) (*ConfigurationVersionList, error)
	// Delete deletes the config version from the store
	DeleteConfigurationVersion(ctx context.Context, id string) error
	// Upload uploads a config tarball for the given config version ID
	UploadConfigurationVersion(ctx context.Context, id string, fn func(cv *ConfigurationVersion, uploader ConfigUploader) error) error
}

// ConfigUploader uploads a config
type ConfigUploader interface {
	// Upload uploads the config tarball and returns a status indicating success
	// or failure.
	Upload(ctx context.Context, config []byte) (ConfigurationStatus, error)
	// SetErrored sets the config version status to 'errored' in the store.
	SetErrored(ctx context.Context) error
}

// ConfigurationVersionGetOptions are options for retrieving a single config
// version. Either ID *or* WorkspaceID must be specfiied.
type ConfigurationVersionGetOptions struct {
	// ID of config version to retrieve
	ID *string

	// Get latest config version for this workspace ID
	WorkspaceID *string

	// A list of relations to include
	Include *string `schema:"include"`
}

// ConfigurationVersionListOptions are options for paginating and filtering a
// list of configuration versions
type ConfigurationVersionListOptions struct {
	// A list of relations to include
	Include *string `schema:"include"`

	ListOptions
}

// NewConfigurationVersion creates a ConfigurationVersion object from scratch
func NewConfigurationVersion(workspaceID string, opts ConfigurationVersionCreateOptions) (*ConfigurationVersion, error) {
	cv := ConfigurationVersion{
		id:            NewID("cv"),
		createdAt:     CurrentTimestamp(),
		autoQueueRuns: DefaultAutoQueueRuns,
		source:        DefaultConfigurationSource,
		workspaceID:   workspaceID,
	}
	cv.updateStatus(ConfigurationPending)

	if opts.AutoQueueRuns != nil {
		cv.autoQueueRuns = *opts.AutoQueueRuns
	}
	if opts.Speculative != nil {
		cv.speculative = *opts.Speculative
	}
	if opts.IngressAttributes != nil {
		cv.ingressAttributes = opts.IngressAttributes
	}
	return &cv, nil
}
