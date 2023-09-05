-- +goose Up
CREATE TABLE IF NOT EXISTS github_apps (
    github_app_id TEXT,
    app_id BIGINT,
    installation_id BIGINT,
    webhook_secret TEXT NOT NULL,
    private_key TEXT NOT NULL,
    organization_name TEXT REFERENCES organizations (name) ON UPDATE CASCADE ON DELETE CASCADE NOT NULL,
    PRIMARY KEY (github_app_id)
);

ALTER TABLE repo_connections
    ADD COLUMN github_app_id TEXT,
    ADD CONSTRAINT github_app_id_fk FOREIGN KEY (github_app_id)
        REFERENCES github_apps ON UPDATE CASCADE ON DELETE CASCADE,
    ALTER COLUMN webhook_id DROP NOT NULL,
    ADD CONSTRAINT webhook_check CHECK (github_app_id IS NOT NULL OR webhook_id IS NOT NULL);

ALTER TABLE vcs_providers
    ADD COLUMN github_app_id TEXT,
    ADD CONSTRAINT github_app_id_fk FOREIGN KEY (github_app_id)
        REFERENCES github_apps ON UPDATE CASCADE ON DELETE CASCADE,
    ALTER COLUMN token DROP NOT NULL,
    ADD CONSTRAINT auth_check CHECK (github_app_id IS NOT NULL OR token IS NOT NULL);

-- +goose Down
ALTER TABLE vcs_providers
    DROP COLUMN github_app_id,
    ALTER COLUMN token SET NOT NULL;

ALTER TABLE repo_connections
    DROP COLUMN github_app_id,
    ALTER COLUMN webhook_id SET NOT NULL;

DROP TABLE IF EXISTS github_apps;
