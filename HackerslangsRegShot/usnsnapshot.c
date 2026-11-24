#include "usnsnapshot.h"
#include "usn.h"
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <tchar.h>
#include <aclapi.h>
#include <sddl.h>

#define USN_BASELINE_MAX_FILE_SIZE (1024UL * 1024UL * 1024UL)

typedef struct {
    WCHAR guid[USN_BASELINE_GUID_CHARS];
    DWORD serial;
    BOOL usable;
    HANDLE handle;
    ULONGLONG journalId;
    USN checkpoint;
    int baselineVolume;
    USN_CHANGE_SET changes;
} SNAPSHOT_VOLUME;

struct USN_SNAPSHOT {
    SNAPSHOT_VOLUME* volumes;
    DWORD volumeCount;
    USN_BASELINE baseline;
};

typedef struct {
    USN_CHANGE_SET* changes;
    USN changedFrom;
} COLLECT_CONTEXT;

static BOOL TrustedSid(PSID sid)
{
    return sid != NULL && (IsWellKnownSid(sid, WinBuiltinAdministratorsSid)
        || IsWellKnownSid(sid, WinLocalSystemSid));
}

static BOOL CanUseJournal(void)
{
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(sid);
    BOOL member = FALSE;

    return CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, sid, &size)
        && CheckTokenMembership(NULL, sid, &member) && member;
}

// A checksum detects damage, not forgery. Reject files replaceable by untrusted owners.
static BOOL TrustedBaselineFile(HANDLE file)
{
    PSECURITY_DESCRIPTOR security = NULL;
    PSID owner;
    PACL dacl;
    SECURITY_DESCRIPTOR_CONTROL control;
    DWORD revision;
    BY_HANDLE_FILE_INFORMATION info;
    DWORD i;
    BOOL trusted = FALSE;
    const DWORD writes = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER
        | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED;

    if (!GetFileInformationByHandle(file, &info)
        || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        || GetSecurityInfo(file, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &owner, NULL, &dacl, NULL, &security) != ERROR_SUCCESS)
        return FALSE;
    if (!TrustedSid(owner) || dacl == NULL
        || !GetSecurityDescriptorControl(security, &control, &revision)
        || !(control & SE_DACL_PROTECTED))
        goto done;
    for (i = 0; i < dacl->AceCount; ++i) {
        ACE_HEADER* header;
        ACCESS_ALLOWED_ACE* ace;

        if (!GetAce(dacl, i, (void**)&header))
            goto done;
        if (header->AceType == ACCESS_DENIED_ACE_TYPE)
            continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE)
            goto done;
        ace = (ACCESS_ALLOWED_ACE*)header;
        if (!(header->AceFlags & INHERIT_ONLY_ACE) && (ace->Mask & writes)
            && !TrustedSid((PSID)&ace->SidStart))
            goto done;
    }
    trusted = TRUE;
done:
    LocalFree(security);
    return trusted;
}

static BOOL CollectChange(const USN_CHANGE* change, void* context)
{
    COLLECT_CONTEXT* collect = context;

    if (change->attributes & FILE_ATTRIBUTE_DIRECTORY)
        return TRUE;
    return UsnChangeSetAdd(collect->changes, change->fileId,
        change->usn >= collect->changedFrom, (change->reason & USN_REASON_CLOSE) != 0);
}

static void LoadBaseline(USN_BASELINE* baseline, LPCTSTR path)
{
    HANDLE file;
    LARGE_INTEGER size;
    BYTE* data = NULL;
    DWORD total = 0;

    ZeroMemory(baseline, sizeof(*baseline));
    if (path == NULL)
        return;
    file = CreateFile(path, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return;
    if (!TrustedBaselineFile(file)) {
        OutputDebugString(TEXT("USN: baseline permissions are not trusted; hashing files normally.\n"));
        CloseHandle(file);
        return;
    }
    if (GetFileSizeEx(file, &size) && size.QuadPart > 0
        && size.QuadPart <= USN_BASELINE_MAX_FILE_SIZE) {
        data = malloc((size_t)size.QuadPart);
        while (data != NULL && total < (DWORD)size.QuadPart) {
            DWORD read;

            if (!ReadFile(file, data + total, (DWORD)size.QuadPart - total, &read, NULL)
                || read == 0)
                break;
            total += read;
        }
    }
    CloseHandle(file);
    if (data != NULL && total == (DWORD)size.QuadPart)
        UsnBaselineParse(data, total, baseline);
    free(data);
}

USN_SNAPSHOT* UsnSnapshotBegin(LPCTSTR baselinePath)
{
    USN_SNAPSHOT* snapshot;

    if (!CanUseJournal()) {
        OutputDebugString(TEXT("USN: administrator token unavailable; using classic enumeration and hashing.\n"));
        return NULL;
    }
    snapshot = calloc(1, sizeof(*snapshot));

    if (snapshot != NULL)
        LoadBaseline(&snapshot->baseline, baselinePath);
    return snapshot;
}

static BOOL OpenJournal(SNAPSHOT_VOLUME* volume, const USN_BASELINE* baseline)
{
    WCHAR path[USN_BASELINE_GUID_CHARS];
    WCHAR fileSystem[MAX_PATH + 1];
    DWORD serial, flags;
    size_t length = wcslen(volume->guid);
    USN_JOURNAL_DATA_V0 journal;
    COLLECT_CONTEXT collect;
    USN start, next;
    int baselineVolume;

    if (length < 2 || volume->guid[length - 1] != L'\\')
        return FALSE;
    memcpy(path, volume->guid, (length - 1) * sizeof(WCHAR));
    path[length - 1] = L'\0';
    volume->handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (volume->handle == INVALID_HANDLE_VALUE)
        return FALSE;
    if (!GetVolumeInformationByHandleW(volume->handle, NULL, 0, &serial, NULL, &flags,
            fileSystem, MAX_PATH + 1)
        || serial != volume->serial || _wcsicmp(fileSystem, L"NTFS") != 0
        || !(flags & FILE_SUPPORTS_USN_JOURNAL)
        || !UsnQueryJournal(volume->handle, &journal))
        return FALSE;

    start = journal.FirstUsn > journal.LowestValidUsn ? journal.FirstUsn : journal.LowestValidUsn;
    collect.changes = &volume->changes;
    collect.changedFrom = MAXLONGLONG;
    baselineVolume = UsnBaselineFindVolume(baseline, volume->guid, serial, journal.UsnJournalID);
    if (baselineVolume >= 0) {
        USN checkpoint = baseline->volumes[baselineVolume].checkpoint;

        if (checkpoint >= start && checkpoint <= journal.NextUsn) {
            collect.changedFrom = checkpoint;
            volume->baselineVolume = baselineVolume;
        }
    }
    if (!UsnReadChanges(volume->handle, journal.UsnJournalID, start, CollectChange,
            &collect, &next))
        return FALSE;
    volume->journalId = journal.UsnJournalID;
    volume->checkpoint = next;
    return TRUE;
}

DWORD UsnSnapshotVolume(USN_SNAPSHOT* snapshot, const WCHAR* volumeGuid, DWORD volumeSerial)
{
    SNAPSHOT_VOLUME* volumes;
    SNAPSHOT_VOLUME* volume;
    DWORD i;

    if (snapshot == NULL || volumeGuid == NULL || volumeGuid[0] == L'\0'
        || wcslen(volumeGuid) >= USN_BASELINE_GUID_CHARS)
        return 0;
    for (i = 0; i < snapshot->volumeCount; ++i) {
        if (wcscmp(snapshot->volumes[i].guid, volumeGuid) == 0)
            return snapshot->volumes[i].usable && snapshot->volumes[i].serial == volumeSerial
                ? i + 1 : 0;
    }
    if (snapshot->volumeCount >= USN_BASELINE_MAX_VOLUMES)
        return 0;
    volumes = realloc(snapshot->volumes, (snapshot->volumeCount + 1) * sizeof(*volumes));
    if (volumes == NULL)
        return 0;
    snapshot->volumes = volumes;
    volume = &volumes[snapshot->volumeCount++];
    ZeroMemory(volume, sizeof(*volume));
    wcscpy_s(volume->guid, USN_BASELINE_GUID_CHARS, volumeGuid);
    volume->serial = volumeSerial;
    volume->baselineVolume = -1;
    volume->usable = OpenJournal(volume, &snapshot->baseline);
    if (!volume->usable) {
        UsnChangeSetFree(&volume->changes);
        volume->baselineVolume = -1;
        if (volume->handle != INVALID_HANDLE_VALUE && volume->handle != NULL)
            CloseHandle(volume->handle);
        volume->handle = NULL;
        return 0;
    }
    return snapshot->volumeCount;
}

static const SNAPSHOT_VOLUME* UsableVolume(const USN_SNAPSHOT* snapshot, DWORD volume)
{
    if (snapshot == NULL || volume == 0 || volume > snapshot->volumeCount
        || !snapshot->volumes[volume - 1].usable)
        return NULL;
    return &snapshot->volumes[volume - 1];
}

BOOL UsnSnapshotReuseHash(const USN_SNAPSHOT* snapshot, DWORD volume, ULONGLONG fileId,
    ULONGLONG size, ULONGLONG writeTime, DWORD attributes, ULONGLONG* hash)
{
    const SNAPSHOT_VOLUME* current = UsableVolume(snapshot, volume);
    const USN_BASELINE_ENTRY* entry;

    if (current == NULL || current->baselineVolume < 0 || hash == NULL)
        return FALSE;
    entry = UsnBaselineFind(&snapshot->baseline, (DWORD)current->baselineVolume, fileId);
    if (!UsnCanReuseHash(entry, UsnChangeSetFlags(&current->changes, fileId),
            size, writeTime, attributes))
        return FALSE;
    *hash = entry->hash;
    return TRUE;
}

BOOL UsnSnapshotCanCache(const USN_SNAPSHOT* snapshot, DWORD volume, ULONGLONG fileId,
    DWORD attributes)
{
    const SNAPSHOT_VOLUME* current = UsableVolume(snapshot, volume);

    return current != NULL
        && UsnCanCacheHash(fileId, UsnChangeSetFlags(&current->changes, fileId), attributes);
}

BOOL UsnSnapshotReadLateChanges(USN_SNAPSHOT* snapshot, DWORD volume, USN_CHANGE_SET* changes)
{
    const SNAPSHOT_VOLUME* current = UsableVolume(snapshot, volume);
    COLLECT_CONTEXT collect;
    USN next;

    if (current == NULL || current->handle == NULL || changes == NULL)
        return FALSE;
    collect.changes = changes;
    collect.changedFrom = current->checkpoint;
    if (UsnReadChanges(current->handle, current->journalId, current->checkpoint,
            CollectChange, &collect, &next))
        return TRUE;
    UsnChangeSetFree(changes);
    return FALSE;
}

void UsnSnapshotEndScan(USN_SNAPSHOT* snapshot)
{
    DWORD i;

    if (snapshot == NULL)
        return;
    for (i = 0; i < snapshot->volumeCount; ++i) {
        UsnChangeSetFree(&snapshot->volumes[i].changes);
        if (snapshot->volumes[i].handle != NULL)
            CloseHandle(snapshot->volumes[i].handle);
        snapshot->volumes[i].handle = NULL;
    }
    UsnBaselineFree(&snapshot->baseline);
}

void UsnSnapshotFree(USN_SNAPSHOT* snapshot)
{
    if (snapshot == NULL)
        return;
    UsnSnapshotEndScan(snapshot);
    free(snapshot->volumes);
    free(snapshot);
}

static BOOL WriteAll(HANDLE file, const BYTE* data, DWORD size)
{
    while (size != 0) {
        DWORD written;

        if (!WriteFile(file, data, size, &written, NULL) || written == 0)
            return FALSE;
        data += written;
        size -= written;
    }
    return TRUE;
}

static BOOL ReplaceFileAtomically(LPCTSTR path, const BYTE* data, DWORD size)
{
    size_t length = _tcslen(path) + 5;
    LPTSTR temporary = malloc(length * sizeof(TCHAR));
    HANDLE file;
    BOOL result = FALSE;
    PSECURITY_DESCRIPTOR security = NULL;
    SECURITY_ATTRIBUTES attributes;

    if (temporary == NULL)
        return FALSE;
    _tcscpy_s(temporary, length, path);
    _tcscat_s(temporary, length, TEXT(".tmp"));
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
            TEXT("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"),
            SDDL_REVISION_1, &security, NULL)) {
        free(temporary);
        return FALSE;
    }
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = security;
    attributes.bInheritHandle = FALSE;
    // Never truncate an existing temp file (which may be a planted hard link).
    file = CreateFile(temporary, GENERIC_WRITE | READ_CONTROL, 0, &attributes, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        result = TrustedBaselineFile(file) && WriteAll(file, data, size) && FlushFileBuffers(file);
        if (!CloseHandle(file))
            result = FALSE;
        if (result)
            result = MoveFileEx(temporary, path,
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        if (!result)
            DeleteFile(temporary);
    }
    LocalFree(security);
    free(temporary);
    return result;
}

BOOL UsnSnapshotSaveBaseline(const USN_SNAPSHOT* snapshot, USN_BASELINE_ENTRY* entries,
    DWORD entryCount, LPCTSTR baselinePath)
{
    USN_BASELINE baseline;
    DWORD remap[USN_BASELINE_MAX_VOLUMES];
    DWORD i, kept = 0;
    BYTE* data;
    DWORD size;
    BOOL result;

    if (snapshot == NULL || baselinePath == NULL || (entryCount != 0 && entries == NULL))
        return FALSE;
    ZeroMemory(&baseline, sizeof(baseline));
    if (snapshot->volumeCount != 0) {
        baseline.volumes = calloc(snapshot->volumeCount, sizeof(*baseline.volumes));
        if (baseline.volumes == NULL)
            return FALSE;
    }
    for (i = 0; i < snapshot->volumeCount; ++i) {
        const SNAPSHOT_VOLUME* volume = &snapshot->volumes[i];

        remap[i] = MAXDWORD;
        if (!volume->usable)
            continue;
        remap[i] = baseline.volumeCount;
        wcscpy_s(baseline.volumes[baseline.volumeCount].volumeGuid,
            USN_BASELINE_GUID_CHARS, volume->guid);
        baseline.volumes[baseline.volumeCount].journalId = volume->journalId;
        baseline.volumes[baseline.volumeCount].checkpoint = volume->checkpoint;
        baseline.volumes[baseline.volumeCount].volumeSerial = volume->serial;
        ++baseline.volumeCount;
    }
    for (i = 0; i < entryCount; ++i) {
        if (entries[i].volume < snapshot->volumeCount
            && remap[entries[i].volume] != MAXDWORD) {
            entries[kept] = entries[i];
            entries[kept].volume = remap[entries[i].volume];
            ++kept;
        }
    }
    UsnBaselineNormalizeEntries(entries, &kept);
    baseline.entries = entries;
    baseline.entryCount = kept;
    result = UsnBaselineSerialize(&baseline, &data, &size);
    free(baseline.volumes);
    if (!result)
        return FALSE;
    result = ReplaceFileAtomically(baselinePath, data, size);
    free(data);
    return result;
}
