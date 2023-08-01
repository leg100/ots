// Code generated by "stringer -type Action ./internal/rbac"; DO NOT EDIT.

package rbac

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[WatchAction-0]
	_ = x[CreateOrganizationAction-1]
	_ = x[UpdateOrganizationAction-2]
	_ = x[GetOrganizationAction-3]
	_ = x[ListOrganizationsAction-4]
	_ = x[GetEntitlementsAction-5]
	_ = x[DeleteOrganizationAction-6]
	_ = x[CreateVCSProviderAction-7]
	_ = x[GetVCSProviderAction-8]
	_ = x[ListVCSProvidersAction-9]
	_ = x[DeleteVCSProviderAction-10]
	_ = x[CreateAgentTokenAction-11]
	_ = x[ListAgentTokensAction-12]
	_ = x[DeleteAgentTokenAction-13]
	_ = x[CreateOrganizationTokenAction-14]
	_ = x[DeleteOrganizationTokenAction-15]
	_ = x[CreateRunTokenAction-16]
	_ = x[CreateModuleAction-17]
	_ = x[CreateModuleVersionAction-18]
	_ = x[UpdateModuleAction-19]
	_ = x[ListModulesAction-20]
	_ = x[GetModuleAction-21]
	_ = x[DeleteModuleAction-22]
	_ = x[DeleteModuleVersionAction-23]
	_ = x[CreateVariableAction-24]
	_ = x[UpdateVariableAction-25]
	_ = x[ListVariablesAction-26]
	_ = x[GetVariableAction-27]
	_ = x[DeleteVariableAction-28]
	_ = x[GetRunAction-29]
	_ = x[ListRunsAction-30]
	_ = x[ApplyRunAction-31]
	_ = x[CreateRunAction-32]
	_ = x[DiscardRunAction-33]
	_ = x[DeleteRunAction-34]
	_ = x[CancelRunAction-35]
	_ = x[EnqueuePlanAction-36]
	_ = x[StartPhaseAction-37]
	_ = x[FinishPhaseAction-38]
	_ = x[PutChunkAction-39]
	_ = x[TailLogsAction-40]
	_ = x[GetPlanFileAction-41]
	_ = x[UploadPlanFileAction-42]
	_ = x[GetLockFileAction-43]
	_ = x[UploadLockFileAction-44]
	_ = x[ListWorkspacesAction-45]
	_ = x[GetWorkspaceAction-46]
	_ = x[CreateWorkspaceAction-47]
	_ = x[DeleteWorkspaceAction-48]
	_ = x[SetWorkspacePermissionAction-49]
	_ = x[UnsetWorkspacePermissionAction-50]
	_ = x[UpdateWorkspaceAction-51]
	_ = x[ListTagsAction-52]
	_ = x[DeleteTagsAction-53]
	_ = x[TagWorkspacesAction-54]
	_ = x[AddTagsAction-55]
	_ = x[RemoveTagsAction-56]
	_ = x[ListWorkspaceTags-57]
	_ = x[ListRemoteStateConsumersAction-58]
	_ = x[ReplaceRemoteStateConsumersAction-59]
	_ = x[AddRemoteStateConsumersAction-60]
	_ = x[DeleteRemoteStateConsumersAction-61]
	_ = x[LockWorkspaceAction-62]
	_ = x[UnlockWorkspaceAction-63]
	_ = x[ForceUnlockWorkspaceAction-64]
	_ = x[CreateStateVersionAction-65]
	_ = x[ListStateVersionsAction-66]
	_ = x[GetStateVersionAction-67]
	_ = x[DeleteStateVersionAction-68]
	_ = x[RollbackStateVersionAction-69]
	_ = x[DownloadStateAction-70]
	_ = x[GetStateVersionOutputAction-71]
	_ = x[CreateConfigurationVersionAction-72]
	_ = x[ListConfigurationVersionsAction-73]
	_ = x[GetConfigurationVersionAction-74]
	_ = x[DownloadConfigurationVersionAction-75]
	_ = x[DeleteConfigurationVersionAction-76]
	_ = x[CreateUserAction-77]
	_ = x[ListUsersAction-78]
	_ = x[GetUserAction-79]
	_ = x[DeleteUserAction-80]
	_ = x[CreateTeamAction-81]
	_ = x[UpdateTeamAction-82]
	_ = x[GetTeamAction-83]
	_ = x[ListTeamsAction-84]
	_ = x[DeleteTeamAction-85]
	_ = x[AddTeamMembershipAction-86]
	_ = x[RemoveTeamMembershipAction-87]
	_ = x[CreateNotificationConfigurationAction-88]
	_ = x[UpdateNotificationConfigurationAction-89]
	_ = x[ListNotificationConfigurationsAction-90]
	_ = x[GetNotificationConfigurationAction-91]
	_ = x[DeleteNotificationConfigurationAction-92]
}

const _Action_name = "WatchActionCreateOrganizationActionUpdateOrganizationActionGetOrganizationActionListOrganizationsActionGetEntitlementsActionDeleteOrganizationActionCreateVCSProviderActionGetVCSProviderActionListVCSProvidersActionDeleteVCSProviderActionCreateAgentTokenActionListAgentTokensActionDeleteAgentTokenActionCreateOrganizationTokenActionDeleteOrganizationTokenActionCreateRunTokenActionCreateModuleActionCreateModuleVersionActionUpdateModuleActionListModulesActionGetModuleActionDeleteModuleActionDeleteModuleVersionActionCreateVariableActionUpdateVariableActionListVariablesActionGetVariableActionDeleteVariableActionGetRunActionListRunsActionApplyRunActionCreateRunActionDiscardRunActionDeleteRunActionCancelRunActionEnqueuePlanActionStartPhaseActionFinishPhaseActionPutChunkActionTailLogsActionGetPlanFileActionUploadPlanFileActionGetLockFileActionUploadLockFileActionListWorkspacesActionGetWorkspaceActionCreateWorkspaceActionDeleteWorkspaceActionSetWorkspacePermissionActionUnsetWorkspacePermissionActionUpdateWorkspaceActionListTagsActionDeleteTagsActionTagWorkspacesActionAddTagsActionRemoveTagsActionListWorkspaceTagsListRemoteStateConsumersActionReplaceRemoteStateConsumersActionAddRemoteStateConsumersActionDeleteRemoteStateConsumersActionLockWorkspaceActionUnlockWorkspaceActionForceUnlockWorkspaceActionCreateStateVersionActionListStateVersionsActionGetStateVersionActionDeleteStateVersionActionRollbackStateVersionActionDownloadStateActionGetStateVersionOutputActionCreateConfigurationVersionActionListConfigurationVersionsActionGetConfigurationVersionActionDownloadConfigurationVersionActionDeleteConfigurationVersionActionCreateUserActionListUsersActionGetUserActionDeleteUserActionCreateTeamActionUpdateTeamActionGetTeamActionListTeamsActionDeleteTeamActionAddTeamMembershipActionRemoveTeamMembershipActionCreateNotificationConfigurationActionUpdateNotificationConfigurationActionListNotificationConfigurationsActionGetNotificationConfigurationActionDeleteNotificationConfigurationAction"

var _Action_index = [...]uint16{0, 11, 35, 59, 80, 103, 124, 148, 171, 191, 213, 236, 258, 279, 301, 330, 359, 379, 397, 422, 440, 457, 472, 490, 515, 535, 555, 574, 591, 611, 623, 637, 651, 666, 682, 697, 712, 729, 745, 762, 776, 790, 807, 827, 844, 864, 884, 902, 923, 944, 972, 1002, 1023, 1037, 1053, 1072, 1085, 1101, 1118, 1148, 1181, 1210, 1242, 1261, 1282, 1308, 1332, 1355, 1376, 1400, 1426, 1445, 1472, 1504, 1535, 1564, 1598, 1630, 1646, 1661, 1674, 1690, 1706, 1722, 1735, 1750, 1766, 1789, 1815, 1852, 1889, 1925, 1959, 1996}

func (i Action) String() string {
	if i < 0 || i >= Action(len(_Action_index)-1) {
		return "Action(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _Action_name[_Action_index[i]:_Action_index[i+1]]
}
