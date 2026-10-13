-- The id_token claims PM_OIDC_USER_ATTRIBUTES declares, as of the user's last login; Cedar User attributes.
ALTER TABLE app_user ADD COLUMN attributes JSONB NOT NULL DEFAULT '{}'::jsonb;
