ALTER TABLE txos ADD COLUMN minted_account_id_hex TEXT NULL;
ALTER TABLE txos ADD COLUMN received_account_id_hex TEXT NULL;
-- todo: data migration
-- todo: remove accounttxostatus