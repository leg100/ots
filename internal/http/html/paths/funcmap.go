// Code generated by "go generate"; DO NOT EDIT.

package paths

import (
	"text/template"
)

var funcmap = template.FuncMap{}

func init() {
	funcmap["adminPath"] = Admin

	funcmap["loginPath"] = Login

	funcmap["logoutPath"] = Logout

	funcmap["adminLoginPath"] = AdminLogin

	funcmap["profilePath"] = Profile

	funcmap["tokensPath"] = Tokens

	funcmap["deleteTokenPath"] = DeleteToken

	funcmap["newTokenPath"] = NewToken

	funcmap["createTokenPath"] = CreateToken

	funcmap["githubAppsPath"] = GithubApps
	funcmap["createGithubAppPath"] = CreateGithubApp
	funcmap["newGithubAppPath"] = NewGithubApp
	funcmap["githubAppPath"] = GithubApp
	funcmap["editGithubAppPath"] = EditGithubApp
	funcmap["updateGithubAppPath"] = UpdateGithubApp
	funcmap["deleteGithubAppPath"] = DeleteGithubApp
	funcmap["exchangeCodeGithubAppPath"] = ExchangeCodeGithubApp
	funcmap["completeGithubAppPath"] = CompleteGithubApp
	funcmap["deleteInstallGithubAppPath"] = DeleteInstallGithubApp

	funcmap["organizationsPath"] = Organizations
	funcmap["createOrganizationPath"] = CreateOrganization
	funcmap["newOrganizationPath"] = NewOrganization
	funcmap["organizationPath"] = Organization
	funcmap["editOrganizationPath"] = EditOrganization
	funcmap["updateOrganizationPath"] = UpdateOrganization
	funcmap["deleteOrganizationPath"] = DeleteOrganization

	funcmap["workspacesPath"] = Workspaces
	funcmap["createWorkspacePath"] = CreateWorkspace
	funcmap["newWorkspacePath"] = NewWorkspace
	funcmap["workspacePath"] = Workspace
	funcmap["editWorkspacePath"] = EditWorkspace
	funcmap["updateWorkspacePath"] = UpdateWorkspace
	funcmap["deleteWorkspacePath"] = DeleteWorkspace
	funcmap["lockWorkspacePath"] = LockWorkspace
	funcmap["unlockWorkspacePath"] = UnlockWorkspace
	funcmap["forceUnlockWorkspacePath"] = ForceUnlockWorkspace
	funcmap["setPermissionWorkspacePath"] = SetPermissionWorkspace
	funcmap["unsetPermissionWorkspacePath"] = UnsetPermissionWorkspace
	funcmap["watchWorkspacePath"] = WatchWorkspace
	funcmap["connectWorkspacePath"] = ConnectWorkspace
	funcmap["disconnectWorkspacePath"] = DisconnectWorkspace
	funcmap["startRunWorkspacePath"] = StartRunWorkspace
	funcmap["setupConnectionProviderWorkspacePath"] = SetupConnectionProviderWorkspace
	funcmap["setupConnectionRepoWorkspacePath"] = SetupConnectionRepoWorkspace
	funcmap["createTagWorkspacePath"] = CreateTagWorkspace
	funcmap["deleteTagWorkspacePath"] = DeleteTagWorkspace
	funcmap["resourcesWorkspacePath"] = ResourcesWorkspace
	funcmap["outputsWorkspacePath"] = OutputsWorkspace
	funcmap["poolsWorkspacePath"] = PoolsWorkspace

	funcmap["runsPath"] = Runs
	funcmap["createRunPath"] = CreateRun
	funcmap["newRunPath"] = NewRun
	funcmap["runPath"] = Run
	funcmap["editRunPath"] = EditRun
	funcmap["updateRunPath"] = UpdateRun
	funcmap["deleteRunPath"] = DeleteRun
	funcmap["applyRunPath"] = ApplyRun
	funcmap["discardRunPath"] = DiscardRun
	funcmap["cancelRunPath"] = CancelRun
	funcmap["forceCancelRunPath"] = ForceCancelRun
	funcmap["retryRunPath"] = RetryRun
	funcmap["tailRunPath"] = TailRun
	funcmap["widgetRunPath"] = WidgetRun

	funcmap["variablesPath"] = Variables
	funcmap["createVariablePath"] = CreateVariable
	funcmap["newVariablePath"] = NewVariable
	funcmap["variablePath"] = Variable
	funcmap["editVariablePath"] = EditVariable
	funcmap["updateVariablePath"] = UpdateVariable
	funcmap["deleteVariablePath"] = DeleteVariable

	funcmap["runnersPath"] = Runners
	funcmap["createRunnerPath"] = CreateRunner
	funcmap["newRunnerPath"] = NewRunner
	funcmap["runnerPath"] = Runner
	funcmap["editRunnerPath"] = EditRunner
	funcmap["updateRunnerPath"] = UpdateRunner
	funcmap["deleteRunnerPath"] = DeleteRunner
	funcmap["watchRunnerPath"] = WatchRunner

	funcmap["agentPoolsPath"] = AgentPools
	funcmap["createAgentPoolPath"] = CreateAgentPool
	funcmap["newAgentPoolPath"] = NewAgentPool
	funcmap["agentPoolPath"] = AgentPool
	funcmap["editAgentPoolPath"] = EditAgentPool
	funcmap["updateAgentPoolPath"] = UpdateAgentPool
	funcmap["deleteAgentPoolPath"] = DeleteAgentPool

	funcmap["agentTokensPath"] = AgentTokens
	funcmap["createAgentTokenPath"] = CreateAgentToken
	funcmap["newAgentTokenPath"] = NewAgentToken
	funcmap["agentTokenPath"] = AgentToken
	funcmap["editAgentTokenPath"] = EditAgentToken
	funcmap["updateAgentTokenPath"] = UpdateAgentToken
	funcmap["deleteAgentTokenPath"] = DeleteAgentToken

	funcmap["variableSetsPath"] = VariableSets
	funcmap["createVariableSetPath"] = CreateVariableSet
	funcmap["newVariableSetPath"] = NewVariableSet
	funcmap["variableSetPath"] = VariableSet
	funcmap["editVariableSetPath"] = EditVariableSet
	funcmap["updateVariableSetPath"] = UpdateVariableSet
	funcmap["deleteVariableSetPath"] = DeleteVariableSet

	funcmap["variableSetVariablesPath"] = VariableSetVariables
	funcmap["createVariableSetVariablePath"] = CreateVariableSetVariable
	funcmap["newVariableSetVariablePath"] = NewVariableSetVariable
	funcmap["variableSetVariablePath"] = VariableSetVariable
	funcmap["editVariableSetVariablePath"] = EditVariableSetVariable
	funcmap["updateVariableSetVariablePath"] = UpdateVariableSetVariable
	funcmap["deleteVariableSetVariablePath"] = DeleteVariableSetVariable

	funcmap["organizationTokenPath"] = OrganizationToken
	funcmap["createOrganizationTokenPath"] = CreateOrganizationToken
	funcmap["deleteOrganizationTokenPath"] = DeleteOrganizationToken

	funcmap["usersPath"] = Users
	funcmap["createUserPath"] = CreateUser
	funcmap["newUserPath"] = NewUser
	funcmap["userPath"] = User
	funcmap["editUserPath"] = EditUser
	funcmap["updateUserPath"] = UpdateUser
	funcmap["deleteUserPath"] = DeleteUser

	funcmap["teamsPath"] = Teams
	funcmap["createTeamPath"] = CreateTeam
	funcmap["newTeamPath"] = NewTeam
	funcmap["teamPath"] = Team
	funcmap["editTeamPath"] = EditTeam
	funcmap["updateTeamPath"] = UpdateTeam
	funcmap["deleteTeamPath"] = DeleteTeam
	funcmap["addMemberTeamPath"] = AddMemberTeam
	funcmap["removeMemberTeamPath"] = RemoveMemberTeam

	funcmap["vcsProvidersPath"] = VCSProviders
	funcmap["createVCSProviderPath"] = CreateVCSProvider
	funcmap["newVCSProviderPath"] = NewVCSProvider
	funcmap["vcsProviderPath"] = VCSProvider
	funcmap["editVCSProviderPath"] = EditVCSProvider
	funcmap["updateVCSProviderPath"] = UpdateVCSProvider
	funcmap["deleteVCSProviderPath"] = DeleteVCSProvider
	funcmap["newGithubAppVCSProviderPath"] = NewGithubAppVCSProvider

	funcmap["modulesPath"] = Modules
	funcmap["createModulePath"] = CreateModule
	funcmap["newModulePath"] = NewModule
	funcmap["modulePath"] = Module
	funcmap["editModulePath"] = EditModule
	funcmap["updateModulePath"] = UpdateModule
	funcmap["deleteModulePath"] = DeleteModule
}

func FuncMap() template.FuncMap { return funcmap }
