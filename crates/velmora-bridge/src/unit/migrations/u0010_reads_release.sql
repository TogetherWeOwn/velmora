-- Package 5b (docs/units.md, "Reservations", "Keys", "Management
-- reads"; AM-72, AM-73, L1-Q16). Applied at birth, after u0009, in the
-- same transaction.

-- Every admit of a reservation (the first ask and each re-ask) raises
-- `asks` and answers it. `release(rid, asks)` deletes the row only while
-- it still holds that number, so a caller whose answer an admit has
-- overtaken releases nothing (AM-72).
ALTER TABLE unit_reservations ADD COLUMN asks INTEGER NOT NULL DEFAULT 1
  CHECK (asks >= 1);

-- `owner_ref` is write-once per principal row (AM-72): an entry with
-- another non-null value keeps the stored one, applies its other fields
-- and marks the row here, once per value it brought. While a mark is
-- set, every acting lookup of that principal, by id or by either value,
-- answers `owner_ref_ambiguous` (fails closed). Only an operator clears
-- it. Not a key table: the move applies the chain itself and makes the
-- same marks (export hashes `unit_keys` only).
CREATE TABLE unit_owner_ref_conflicts (
  id          TEXT NOT NULL REFERENCES unit_keys(id),
  disputed    TEXT NOT NULL,
  marked_at   INTEGER NOT NULL,
  seq         INTEGER NOT NULL CHECK (seq >= 1),
  PRIMARY KEY (id, disputed)
) WITHOUT ROWID;
CREATE INDEX unit_owner_ref_conflicts_by_value ON unit_owner_ref_conflicts(disputed);

-- `keys_page` (the management plane's key list): S3 keys or app
-- passwords that are not revoked, in creation order, then id. Partial,
-- so a principal lookup by `owner_ref` keeps its own index
-- (`unit_keys_by_owner_ref`), and revoked rows, which are kept for good,
-- cost a page nothing; the queries name the same terms.
CREATE INDEX unit_keys_by_kind_created ON unit_keys(kind, created_at, id)
  WHERE kind IN ('s3', 'app_password') AND status <> 'revoked';
