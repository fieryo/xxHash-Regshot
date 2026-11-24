#ifndef REGSHOT_USNBASELINE_H
#define REGSHOT_USNBASELINE_H

#include <windows.h>

#define USN_BASELINE_GUID_CHARS 64
#define USN_BASELINE_MAX_VOLUMES 256
#define USN_BASELINE_HASH_XXH3_64 1

/* Volume GUID path, e.g. \\?\Volume{...}\, plus its journal checkpoint. */
typedef struct {
    WCHAR volumeGuid[USN_BASELINE_GUID_CHARS];
    ULONGLONG journalId;
    LONGLONG checkpoint;
    DWORD volumeSerial;
    DWORD reserved;
} USN_BASELINE_VOLUME;

/* File content hash keyed by volume index and NTFS file reference number. */
typedef struct {
    ULONGLONG fileId;
    ULONGLONG size;
    ULONGLONG writeTime;
    ULONGLONG hash;
    DWORD volume;
    DWORD attributes;
} USN_BASELINE_ENTRY;

typedef struct {
    USN_BASELINE_VOLUME* volumes;
    DWORD volumeCount;
    USN_BASELINE_ENTRY* entries;
    DWORD entryCount;
} USN_BASELINE;

#define USN_FILE_CHANGED 0x01
#define USN_FILE_OPEN 0x02

typedef struct {
    ULONGLONG* keys;
    BYTE* flags;
    DWORD capacity;
    DWORD count;
} USN_CHANGE_SET;

/* Entries must be sorted and unique; see UsnBaselineNormalizeEntries. */
BOOL UsnBaselineSerialize(const USN_BASELINE* baseline, BYTE** data, DWORD* size);
BOOL UsnBaselineParse(const BYTE* data, DWORD size, USN_BASELINE* baseline);
void UsnBaselineFree(USN_BASELINE* baseline);

/* Sorts by volume/file ID and drops IDs seen with conflicting data. */
void UsnBaselineNormalizeEntries(USN_BASELINE_ENTRY* entries, DWORD* count);
const USN_BASELINE_ENTRY* UsnBaselineFind(const USN_BASELINE* baseline,
    DWORD volume, ULONGLONG fileId);
int UsnBaselineFindVolume(const USN_BASELINE* baseline, const WCHAR* volumeGuid,
    DWORD volumeSerial, ULONGLONG journalId);

/* Records must be added in journal order. */
BOOL UsnChangeSetAdd(USN_CHANGE_SET* set, ULONGLONG fileId, BOOL changed, BOOL closed);
DWORD UsnChangeSetFlags(const USN_CHANGE_SET* set, ULONGLONG fileId);
void UsnChangeSetFree(USN_CHANGE_SET* set);

BOOL UsnCanReuseHash(const USN_BASELINE_ENTRY* entry, DWORD changeFlags,
    ULONGLONG size, ULONGLONG writeTime, DWORD attributes);
BOOL UsnCanCacheHash(ULONGLONG fileId, DWORD changeFlags, DWORD attributes);

#endif
