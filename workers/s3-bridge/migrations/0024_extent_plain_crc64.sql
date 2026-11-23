-- Raw CRC64NVME bytes, big-endian; a D1 number cannot carry all 64 bits.
-- No default or backfill: extents sealed without the checksum stay NULL.
ALTER TABLE extents ADD COLUMN plain_crc64 BLOB;
