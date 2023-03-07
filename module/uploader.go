package module

import (
	"context"
)

type uploader struct {
	*pgdb
	statusUpdater
}

// Upload uploads a tarball for a module version.
func (u *uploader) Upload(ctx context.Context, opts UploadModuleVersionOptions) (*Module, *ModuleVersion, error) {
	var mod *Module
	var modver *ModuleVersion

	// check tarball is legit and if not set bad status
	if _, err := UnmarshalTerraformModule(opts.Tarball); err != nil {
		return u.updateStatus(ctx, UpdateModuleVersionStatusOptions{
			ID:     opts.ModuleVersionID,
			Status: ModuleVersionStatusRegIngressFailed,
			Error:  err.Error(),
		})
	}

	// upload tarball and set status
	err := u.tx(ctx, func(tx *pgdb) (err error) {
		modver, err = tx.UpdateModuleVersionStatus(ctx, UpdateModuleVersionStatusOptions{
			ID:     opts.ModuleVersionID,
			Status: ModuleVersionStatusOk,
		})
		if err != nil {
			return err
		}
		return tx.UploadModuleVersion(ctx, opts)
	})
	return mod, modver, err
}