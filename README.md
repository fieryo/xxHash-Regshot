# xxHash-Regshot
An improved version of Regshot with xxHash

File snapshots use the 64-bit XXH3 hash from xxHash 0.8.4. The upstream
x86 dispatcher selects AVX2 when supported, with a fallback on older CPUs.
Files up to 256 KiB use the one-shot XXH3 path without allocating streaming
state; larger files stream through a 256 KiB sequential-read buffer.
XXH3 is non-cryptographic and is not suitable for security verification.

New hive files store hashes and directory scan status in file-content version 4.
They require this updated application; older builds reject version 4 snapshots.
Version 3 hashes remain readable. Older hive files
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
damaged/cyclic hive rejection, directory retry, protected-directory handling,
junction traversal prevention, skipped-directory save/load and comparisons,
save-write failures, and baseline permissions.
Run it elevated for the USN baseline permission tests.

Directory scans request basic directory information and large-fetch
enumeration when supported, falling back to compatible Windows APIs.
An error partway through file-ID enumeration restarts that directory with
classic enumeration. Protected, locked, disappeared, and overlong directory
paths are retained with an unscanned-contents marker instead of discarding
the whole shot. Directory reparse points (including junctions and directory
symlinks) encountered below a scan root are recorded but not traversed, avoiding
cycles and repeated scans of their targets. To scan a target, select it explicitly
as a scan root. A warning and the shot information show the unscanned-directory
count; debugger output includes paths and error codes.

The markers survive saving/loading. If either shot could not scan a directory,
its children are excluded from comparison so unavailable contents are not
reported as added or deleted. Metadata for the directory itself is still compared.
Unexpected enumeration failures still discard the shot rather than silently
accepting damaged enumeration data.
Registry values that grow during enumeration are retried at the same index;
if they cannot be read after bounded retries, the snapshot is also discarded.
Hive loading validates reachable structures, strings, data ranges, and cycles
before replacing the current shot; unsupported format versions are rejected.

**Shot and Save** captures the shot, then opens a **Save As** dialog. It does
not automatically create a snapshot in Temp; choose a filename and confirm
the dialog. A discarded shot or a cancelled dialog creates no snapshot file.
Save-dialog and write failures are reported, and the captured shot remains
in memory so **Save** can be retried.

## USN incremental snapshots (optional)

Check **USN incremental** (next to *Scan dir*) to reuse file hashes from the
most recently saved snapshot. It is off by default and stored as
`UsnIncremental` in `regshot.ini`.

- Directories are still fully enumerated, so new, deleted, renamed, and moved
  files and directories in scanned areas are reported as in a classic scan.
  The same unavailable-directory and reparse-point rules apply. Hashes are
  keyed by NTFS file ID, so moving a directory does not force rehashing.
- A hash is reused only when the volume GUID, serial number, and USN journal ID
  match the baseline, the baseline checkpoint is still in the journal, the
  journal has no record for the file since that checkpoint, the file was not
  left open with unrecorded changes, and its size, write time, and attributes
  are unchanged. File reparse points are always hashed.
- After the scan, records written while scanning are read; reused files that
  changed meanwhile are hashed again.
- Anything else uses the classic scan and hashes the file: no administrator
  rights, non-NTFS volumes, ReFS/V3 records, journal deleted, recreated, or
  wrapped, a missing or corrupt baseline, and enumeration without file IDs.
  Non-elevated runs use classic enumeration immediately. Unusable volumes
  switch to classic enumeration for ordinary descendants; explicitly selected
  scan roots are probed separately because they can be on a different volume.

After a snapshot is saved successfully, `RegshotUsnBaseline.dat` is atomically
replaced next to `regshot.ini` (checksummed volume checkpoints plus file ID,
size, write time, attributes, and XXH3 hash). Saving a snapshot that was not
taken in USN mode, or a failed save, deletes it. Changes made while the volume
was not journaling (for example, offline edits from another OS) can only be
detected through size and write time.
The first shot has no hashes to reuse and must read every accessible file's
contents; USN incremental mode speeds up later shots after a successful save.
Initial full-drive time is therefore still limited by disk throughput,
file count, and antivirus scanning, not just hash computation.

Baselines have a protected DACL and an Administrators owner. Only Administrators
and SYSTEM may write; ordinary users may read. Loading rejects baselines whose
owner, permissions, or reparse-point status are untrusted (including old,
unprotected baselines), and uses full hashing instead. The payload checksum
detects corruption, not tampering. A pre-existing `.tmp` file is never
overwritten; saving then invalidates the baseline and logs the failure.
