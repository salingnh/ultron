-- G1.4a: `asset.normalization_version` tags every minted canonical key with the rules version
-- that produced it (`aegis-norm/<n>`, contracts/ingestion/normalization.v2.yaml, locked at G0.3c).
-- Apply after 0014.
--
-- A stored key is never compared or "upgraded" across rules versions, so a key minted before
-- aegis-norm/1 was recorded must stay untagged: rows that predate this column keep NULL rather
-- than being relabelled as /1 by a backfill. New rows must name their version (INSERT trigger);
-- the value is written once (UPDATE trigger). The version is metadata, not a second identity:
-- `canonical_key` and its detail row remain the identity, and changing the rules is a new version
-- plus an explicit re-key migration, never an in-place edit of this column.
BEGIN;
SET LOCAL search_path = aegis, public;

ALTER TABLE asset ADD COLUMN normalization_version text
  CHECK (normalization_version ~ '^aegis-norm/[1-9][0-9]*$');

CREATE FUNCTION aegis.require_asset_normalization_version() RETURNS trigger
LANGUAGE plpgsql SET search_path = aegis, pg_temp AS $$
BEGIN
  IF NEW.normalization_version IS NULL THEN
    RAISE EXCEPTION 'new asset requires normalization_version (aegis-norm/<n>); an untagged canonical_key cannot be compared or re-keyed across rules versions'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER normalization_version_required BEFORE INSERT ON asset
  FOR EACH ROW EXECUTE FUNCTION aegis.require_asset_normalization_version();

CREATE FUNCTION aegis.keep_asset_normalization_version() RETURNS trigger
LANGUAGE plpgsql SET search_path = aegis, pg_temp AS $$
BEGIN
  IF NEW.normalization_version IS DISTINCT FROM OLD.normalization_version THEN
    RAISE EXCEPTION 'asset.normalization_version is written once; a new aegis-norm/<n> needs a re-key migration, not an UPDATE'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER normalization_version_fixed BEFORE UPDATE ON asset
  FOR EACH ROW EXECUTE FUNCTION aegis.keep_asset_normalization_version();

COMMENT ON COLUMN asset.normalization_version IS
  'aegis-norm/<n> (contracts/ingestion/normalization.v2.yaml) that minted canonical_key. Required on INSERT, written once. NULL only for rows that predate 0015: their key came from no versioned rule set and is never compared with a versioned one. A rules change is a new version plus an explicit re-key migration.';
COMMENT ON FUNCTION aegis.require_asset_normalization_version() IS
  '0015/G1.4a: refuses an asset without a normalization_version, so no new key is untagged.';
COMMENT ON FUNCTION aegis.keep_asset_normalization_version() IS
  '0015/G1.4a: normalization_version is immutable; re-labelling a stored key would claim a rules version it was not minted with.';

COMMIT;
