#ifndef REGSHOT_USNSNAPSHOT_H
#define REGSHOT_USNSNAPSHOT_H

#include <windows.h>
#include "usnbaseline.h"

typedef struct USN_SNAPSHOT USN_SNAPSHOT;

/* Loads the saved baseline if valid; a missing or invalid one only disables reuse. */
USN_SNAPSHOT* UsnSnapshotBegin(LPCTSTR baselinePath);

/*
 * Returns a 1-based volume index when the volume's USN journal was read
 * successfully, otherwise 0 (classic hashing, nothing cached).
 */
DWORD UsnSnapshotVolume(USN_SNAPSHOT* snapshot, const WCHAR* volumeGuid, DWORD volumeSerial);

BOOL UsnSnapshotReuseHash(const USN_SNAPSHOT* snapshot, DWORD volume, ULONGLONG fileId,
    ULONGLONG size, ULONGLONG writeTime, DWORD attributes, ULONGLONG* hash);
BOOL UsnSnapshotCanCache(const USN_SNAPSHOT* snapshot, DWORD volume, ULONGLONG fileId,
    DWORD attributes);

/*
 * Reads changes made after the volume checkpoint while the scan ran. Returns
 * FALSE when that cannot be proven, in which case every reused hash on the
 * volume must be recomputed.
 */
BOOL UsnSnapshotReadLateChanges(USN_SNAPSHOT* snapshot, DWORD volume, USN_CHANGE_SET* changes);

/* Releases journal data and the loaded baseline; volume checkpoints remain. */
void UsnSnapshotEndScan(USN_SNAPSHOT* snapshot);
void UsnSnapshotFree(USN_SNAPSHOT* snapshot);

/* Entries use 0-based snapshot volume indexes. Replaces the file atomically. */
BOOL UsnSnapshotSaveBaseline(const USN_SNAPSHOT* snapshot, USN_BASELINE_ENTRY* entries,
    DWORD entryCount, LPCTSTR baselinePath);

#endif
