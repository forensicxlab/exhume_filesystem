# exhume_filesystem

The `exhume_filesystem` documentation is maintained at [forensicxlab.com](https://www.forensicxlab.com/docs/exhume_filesystem/getting-started).

## 0.5.6

- Use `exhume_exfat 0.1.13` for prefix and slice reads without allocating the
  entire file. Uninitialized file tails read as zeroes; corrupt cluster chains
  return errors.
- Read APFS compressed resource forks through bounded ranges, decoding and
  caching one 64 KiB chunk at a time. Cache uncompressed extent metadata for
  repeated reads and report overlapping, encrypted, or unreadable extents.
- Expose `FolderFS::open_verified_regular` for sequential readers. Each call
  opens an independent file position and verifies that the handle refers to the
  indexed regular-file identity, without following a final symlink.

APFS range reads cap resource tables at 4 MiB and compressed chunks at 1 MiB.
Inline compressed attributes and their decoded content are capped at 8 MiB;
larger inline files return an explicit error. These are payload limits, not a
fixed total-memory guarantee: filesystem metadata and extent caches can grow
with the evidence. The legacy full-file read API retains its existing limits.
