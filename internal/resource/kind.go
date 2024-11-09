package resource

type Kind string

func (k Kind) String() string {
	return string(k)
}

const (
	OrganizationKind              Kind = "org"
	WorkspaceKind                 Kind = "ws"
	RunKind                       Kind = "run"
	JobKind                       Kind = "job"
	ChunkKind                     Kind = "chunk"
	UserKind                      Kind = "user"
	TeamKind                      Kind = "team"
	NotificationConfigurationKind Kind = "nc"
	AgentPoolKind                 Kind = "apool"
	RunnerKind                    Kind = "runner"
	StateVersionKind              Kind = "sv"
	StateVersionOutputKind        Kind = "wsout"

	OrganizationTokenKind Kind = "ot"
	UserTokenKind         Kind = "ut"
	TeamTokenKind         Kind = "tt"
	AgentTokenKind        Kind = "at"
)