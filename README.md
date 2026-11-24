# xxHash-Regshot
An improved version of Regshot with xxHash

File snapshots use the 64-bit XXH3 hash from xxHash 0.8.4. The upstream
x86 dispatcher selects AVX2 when supported, with a fallback on older CPUs.
XXH3 is non-cryptographic and is not suitable for security verification.

New hive files store hashes in file-content version 3. Older hive files
can still be loaded, but their file hashes are unknown, so comparisons
with them rely on file metadata. Hashing failures are written to the
Windows debugger output and likewise leave the hash unknown.

xxHash is distributed under the BSD 2-Clause license; see
`HackerslangsRegShot/third_party/xxhash/LICENSE`.

## Windows x64 build

The Windows build workflow runs on pushes, pull requests, or manually from
the Actions tab. Download the `xxHash-Regshot-windows-x64` artifact from a
successful run to get `HackerslangsRegShot.exe`.

Run `tests\run-checksum-test.cmd` from a Visual Studio Developer Command
Prompt to test empty, binary, multi-buffer, and unreadable file hashing,
directory enumeration fallback behavior, USN journal reading, and USN
baseline validation and hash reuse rules.
The runner also covers Unicode registry reports, registry-value growth,
damaged/cyclic hive rejection, directory retry, and baseline permissions.
Run it elevated for the USN baseline permission tests.

Directory scans request basic directory information and large-fetch
enumeration when supported, falling back to compatible Windows APIs.
An error partway through file-ID enumeration restarts that directory with
classic enumeration. If classic enumeration fails, the incomplete snapshot
is discarded with an error, rather than reporting unscanned files as deleted.
Exclude inaccessible directories when scanning protected system folders.
Registry values that grow during enumeration are retried at the same index;
if they cannot be read after bounded retries, the snapshot is also discarded.
Hive loading validates reachable structures, strings, data ranges, and cycles
before replacing the current shot; unsupported format versions are rejected.

## USN incremental snapshots (optional)

Check **USN incremental** (next to *Scan dir*) to reuse file hashes from the
most recently saved snapshot. It is off by default and stored as
`UsnIncremental` in `regshot.ini`.

- Directories are still fully enumerated, so new, deleted, renamed, and moved
  files and directories are reported exactly as in a classic scan. Hashes are
  keyed by NTFS file ID, so moving a directory does not force rehashing.
- A hash is reused only when the volume GUID, serial number, and USN journal ID
  match the baseline, the baseline checkpoint is still in the journal, the
  journal has no record for the file since that checkpoint, the file was not
  left open with unrecorded changes, and its size, write time, and attributes
  are unchanged. Reparse points are always hashed.
- After the scan, records written while scanning are read; reused files that
  changed meanwhile are hashed again.
- Anything else uses the classic scan and hashes the file: no administrator
  rights, non-NTFS volumes, ReFS/V3 records, journal deleted, recreated, or
  wrapped, a missing or corrupt baseline, and enumeration without file IDs.
  Non-elevated runs use classic enumeration immediately. Unusable volumes
  switch to classic enumeration for ordinary descendants; reparse points
  are probed separately because they can lead to a different volume.

After a snapshot is saved successfully, `RegshotUsnBaseline.dat` is atomically
replaced next to `regshot.ini` (checksummed volume checkpoints plus file ID,
size, write time, attributes, and XXH3 hash). Saving a snapshot that was not
taken in USN mode, or a failed save, deletes it. Changes made while the volume
was not journaling (for example, offline edits from another OS) can only be
detected through size and write time.

Baselines have a protected DACL and an Administrators owner. Only Administrators
and SYSTEM may write; ordinary users may read. Loading rejects baselines whose
owner, permissions, or reparse-point status are untrusted (including old,
unprotected baselines), and uses full hashing instead. The payload checksum
detects corruption, not tampering. A pre-existing `.tmp` file is never
overwritten; saving then invalidates the baseline and logs the failure.
