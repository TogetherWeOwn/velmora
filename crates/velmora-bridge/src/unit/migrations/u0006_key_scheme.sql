-- The key scheme follows the tenant (ADR §2.4 rule 13, §3.2;
-- docs/units.md, "Key scheme"). Applied at birth, after u0005, in the
-- same transaction.
--
-- The birth certificate fixes the scheme: 1 for tenant 0, 2 for every
-- other tenant. Every column that holds a wrap whose version byte names
-- the scheme must start with that scheme's byte: `buckets.bdk_wrapped`
-- (the BDK wrap), and `access_keys.secret_wrapped` and
-- `unit_keys.secret_wrapped` (the access-key wrap). A row of the other
-- scheme, a value that is not a blob, or a row written before the unit
-- has its certificate is refused, so a scheme-1 wrap can never sit in a
-- managed tenant's unit and survive its shred. SQLite cannot add a CHECK
-- to an existing table, so the CHECK is a trigger on insert and on
-- update. `extents.wrapped_file_key` is wrapped under the bucket's BDK
-- with the same byte in both schemes, so it names no scheme.

CREATE TRIGGER unit_scheme_bdk_insert BEFORE INSERT ON buckets
WHEN typeof(NEW.bdk_wrapped) <> 'blob'
  OR substr(NEW.bdk_wrapped, 1, 1) IS NOT
     (SELECT CASE key_scheme WHEN 1 THEN x'01' WHEN 2 THEN x'02' END FROM unit_birth WHERE id = 1)
BEGIN
  SELECT RAISE(ABORT, 'unit: key scheme');
END;

CREATE TRIGGER unit_scheme_bdk_update BEFORE UPDATE OF bdk_wrapped ON buckets
WHEN typeof(NEW.bdk_wrapped) <> 'blob'
  OR substr(NEW.bdk_wrapped, 1, 1) IS NOT
     (SELECT CASE key_scheme WHEN 1 THEN x'01' WHEN 2 THEN x'02' END FROM unit_birth WHERE id = 1)
BEGIN
  SELECT RAISE(ABORT, 'unit: key scheme');
END;

CREATE TRIGGER unit_scheme_access_key_insert BEFORE INSERT ON access_keys
WHEN typeof(NEW.secret_wrapped) <> 'blob'
  OR substr(NEW.secret_wrapped, 1, 1) IS NOT
     (SELECT CASE key_scheme WHEN 1 THEN x'01' WHEN 2 THEN x'02' END FROM unit_birth WHERE id = 1)
BEGIN
  SELECT RAISE(ABORT, 'unit: key scheme');
END;

CREATE TRIGGER unit_scheme_access_key_update BEFORE UPDATE OF secret_wrapped ON access_keys
WHEN typeof(NEW.secret_wrapped) <> 'blob'
  OR substr(NEW.secret_wrapped, 1, 1) IS NOT
     (SELECT CASE key_scheme WHEN 1 THEN x'01' WHEN 2 THEN x'02' END FROM unit_birth WHERE id = 1)
BEGIN
  SELECT RAISE(ABORT, 'unit: key scheme');
END;

-- A held or revoked subject may come without its secret, and a principal
-- never has one: only a secret that is there is checked.
CREATE TRIGGER unit_scheme_unit_key_insert BEFORE INSERT ON unit_keys
WHEN NEW.secret_wrapped IS NOT NULL AND (typeof(NEW.secret_wrapped) <> 'blob'
  OR substr(NEW.secret_wrapped, 1, 1) IS NOT
     (SELECT CASE key_scheme WHEN 1 THEN x'01' WHEN 2 THEN x'02' END FROM unit_birth WHERE id = 1))
BEGIN
  SELECT RAISE(ABORT, 'unit: key scheme');
END;

CREATE TRIGGER unit_scheme_unit_key_update BEFORE UPDATE OF secret_wrapped ON unit_keys
WHEN NEW.secret_wrapped IS NOT NULL AND (typeof(NEW.secret_wrapped) <> 'blob'
  OR substr(NEW.secret_wrapped, 1, 1) IS NOT
     (SELECT CASE key_scheme WHEN 1 THEN x'01' WHEN 2 THEN x'02' END FROM unit_birth WHERE id = 1))
BEGIN
  SELECT RAISE(ABORT, 'unit: key scheme');
END;
