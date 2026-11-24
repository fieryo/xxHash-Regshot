#include "fileenum.h"
#include <string.h>
#include <wchar.h>

HANDLE FindFirstSnapshotFile(LPCTSTR pattern, WIN32_FIND_DATA* data)
{
    HANDLE result;
    DWORD error;

    result = FindFirstFileEx(pattern, FindExInfoBasic, data,
        FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH);
    if (result != INVALID_HANDLE_VALUE) {
        return result;
    }

    error = GetLastError();
    if (error != ERROR_INVALID_PARAMETER && error != ERROR_NOT_SUPPORTED
        && error != ERROR_INVALID_FUNCTION) {
        return INVALID_HANDLE_VALUE;
    }

    result = FindFirstFileEx(pattern, FindExInfoBasic, data,
        FindExSearchNameMatch, NULL, 0);
    if (result != INVALID_HANDLE_VALUE) {
        return result;
    }

    error = GetLastError();
    if (error != ERROR_INVALID_PARAMETER && error != ERROR_NOT_SUPPORTED
        && error != ERROR_INVALID_FUNCTION) {
        return INVALID_HANDLE_VALUE;
    }

    return FindFirstFile(pattern, data);
}

#define SNAPSHOT_DIR_BUFFER_SIZE (64 * 1024)
#define SNAPSHOT_DIR_REFILL MAXDWORD

static BOOL OpenClassic(SNAPSHOT_DIR* dir, LPCTSTR pattern,
    WIN32_FIND_DATA* data, ULONGLONG* fileId)
{
    dir->find = FindFirstSnapshotFile(pattern, data);
    *fileId = 0;
    return dir->find != INVALID_HANDLE_VALUE;
}

#ifdef UNICODE
static void CloseIds(SNAPSHOT_DIR* dir)
{
    if (dir->directory != INVALID_HANDLE_VALUE)
        CloseHandle(dir->directory);
    if (dir->buffer != NULL)
        HeapFree(GetProcessHeap(), 0, dir->buffer);
    dir->directory = INVALID_HANDLE_VALUE;
    dir->buffer = NULL;
    dir->ids = FALSE;
}

static BOOL ReadVolumeGuid(SNAPSHOT_DIR* dir)
{
    static const WCHAR prefix[] = L"\\\\?\\Volume{";
    WCHAR* path = (WCHAR*)dir->buffer;
    DWORD capacity = SNAPSHOT_DIR_BUFFER_SIZE / sizeof(WCHAR);
    DWORD length, i;

    length = GetFinalPathNameByHandleW(dir->directory, path, capacity,
        FILE_NAME_NORMALIZED | VOLUME_NAME_GUID);
    if (length == 0 || length >= capacity
        || wcsncmp(path, prefix, (sizeof(prefix) / sizeof(WCHAR)) - 1) != 0)
        return FALSE;
    for (i = 0; i < length && i + 1 < SNAPSHOT_VOLUME_GUID_CHARS; ++i) {
        if (path[i] == L'}' && i + 1 < length && path[i + 1] == L'\\') {
            memcpy(dir->volumeGuid, path, (i + 2) * sizeof(WCHAR));
            dir->volumeGuid[i + 2] = L'\0';
            return i + 2 < SNAPSHOT_VOLUME_GUID_CHARS;
        }
    }
    return FALSE;
}

static BOOL ReadIdEntry(SNAPSHOT_DIR* dir, WIN32_FIND_DATA* data, ULONGLONG* fileId)
{
    const DWORD header = (DWORD)FIELD_OFFSET(FILE_ID_BOTH_DIR_INFO, FileName);
    FILE_ID_BOTH_DIR_INFO* entry;
    DWORD nameChars;

    if (dir->offset == SNAPSHOT_DIR_REFILL) {
        if (!GetFileInformationByHandleEx(dir->directory, FileIdBothDirectoryInfo,
                dir->buffer, SNAPSHOT_DIR_BUFFER_SIZE))
            return FALSE;
        dir->offset = 0;
    }
    if (dir->offset > SNAPSHOT_DIR_BUFFER_SIZE - header) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    entry = (FILE_ID_BOTH_DIR_INFO*)(dir->buffer + dir->offset);
    if (entry->FileNameLength > SNAPSHOT_DIR_BUFFER_SIZE - header - dir->offset
        || (entry->FileNameLength % sizeof(WCHAR)) != 0
        || entry->ShortNameLength > sizeof(entry->ShortName)
        || (entry->NextEntryOffset != 0
            && (entry->NextEntryOffset < header
                || entry->NextEntryOffset > SNAPSHOT_DIR_BUFFER_SIZE - dir->offset
                || (entry->NextEntryOffset % sizeof(LONGLONG)) != 0))) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    nameChars = entry->FileNameLength / sizeof(WCHAR);
    if (nameChars == 0 || nameChars >= MAX_PATH) {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return FALSE;
    }

    ZeroMemory(data, sizeof(*data));
    data->dwFileAttributes = entry->FileAttributes;
    data->ftCreationTime.dwLowDateTime = entry->CreationTime.LowPart;
    data->ftCreationTime.dwHighDateTime = (DWORD)entry->CreationTime.HighPart;
    data->ftLastAccessTime.dwLowDateTime = entry->LastAccessTime.LowPart;
    data->ftLastAccessTime.dwHighDateTime = (DWORD)entry->LastAccessTime.HighPart;
    data->ftLastWriteTime.dwLowDateTime = entry->LastWriteTime.LowPart;
    data->ftLastWriteTime.dwHighDateTime = (DWORD)entry->LastWriteTime.HighPart;
    data->nFileSizeLow = entry->EndOfFile.LowPart;
    data->nFileSizeHigh = (DWORD)entry->EndOfFile.HighPart;
    if (entry->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        data->dwReserved0 = entry->EaSize;
    memcpy(data->cFileName, entry->FileName, entry->FileNameLength);
    memcpy(data->cAlternateFileName, entry->ShortName, entry->ShortNameLength);
    *fileId = (ULONGLONG)entry->FileId.QuadPart;

    dir->offset = entry->NextEntryOffset == 0
        ? SNAPSHOT_DIR_REFILL : dir->offset + entry->NextEntryOffset;
    return TRUE;
}

static BOOL OpenIds(SNAPSHOT_DIR* dir, LPCTSTR pattern, const SNAPSHOT_DIR* parentDir,
    ULONGLONG directoryId, WIN32_FIND_DATA* data, ULONGLONG* fileId, BOOL* fallback)
{
    BY_HANDLE_FILE_INFORMATION info;
    size_t length = wcslen(pattern);
    WCHAR* path;

    *fallback = TRUE;
    if (length < 4 || wcscmp(pattern + length - 4, L"\\*.*") != 0)
        return FALSE;
    dir->buffer = HeapAlloc(GetProcessHeap(), 0, SNAPSHOT_DIR_BUFFER_SIZE);
    if (dir->buffer == NULL)
        return FALSE;
    path = HeapAlloc(GetProcessHeap(), 0, (length - 2) * sizeof(WCHAR));
    if (path == NULL) {
        CloseIds(dir);
        return FALSE;
    }
    memcpy(path, pattern, (length - 3) * sizeof(WCHAR));
    path[length - 3] = L'\0';
    dir->directory = CreateFileW(path, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    HeapFree(GetProcessHeap(), 0, path);
    if (dir->directory == INVALID_HANDLE_VALUE
        || !GetFileInformationByHandle(dir->directory, &info)) {
        CloseIds(dir);
        return FALSE;
    }
    if (parentDir != NULL && parentDir->ids && parentDir->volumeGuid[0] != L'\0'
        && parentDir->volumeSerial == info.dwVolumeSerialNumber && directoryId != 0
        && ((((ULONGLONG)info.nFileIndexHigh) << 32) | info.nFileIndexLow) == directoryId) {
        memcpy(dir->volumeGuid, parentDir->volumeGuid, sizeof(dir->volumeGuid));
    }
    else if (!ReadVolumeGuid(dir)) {
        CloseIds(dir);
        return FALSE;
    }
    dir->volumeSerial = info.dwVolumeSerialNumber;
    if (!GetFileInformationByHandleEx(dir->directory, FileIdBothDirectoryRestartInfo,
            dir->buffer, SNAPSHOT_DIR_BUFFER_SIZE)) {
        DWORD error = GetLastError();

        CloseIds(dir);
        if (error == ERROR_NO_MORE_FILES || error == ERROR_FILE_NOT_FOUND) {
            *fallback = FALSE;
            SetLastError(error);
        }
        return FALSE;
    }
    dir->ids = TRUE;
    dir->offset = 0;
    if (!ReadIdEntry(dir, data, fileId)) {
        DWORD error = GetLastError();

        CloseIds(dir);
        SetLastError(error);
        return FALSE;
    }
    *fallback = FALSE;
    return TRUE;
}
#endif

BOOL SnapshotDirOpen(SNAPSHOT_DIR* dir, LPCTSTR pattern, BOOL wantIds,
    const SNAPSHOT_DIR* parentDir, ULONGLONG directoryId, WIN32_FIND_DATA* data, ULONGLONG* fileId)
{
    ZeroMemory(dir, sizeof(*dir));
    dir->find = INVALID_HANDLE_VALUE;
    dir->directory = INVALID_HANDLE_VALUE;
#ifdef UNICODE
    if (wantIds) {
        BOOL fallback;

        if (OpenIds(dir, pattern, parentDir, directoryId, data, fileId, &fallback))
            return TRUE;
        if (!fallback)
            return FALSE;
    }
#else
    (void)wantIds;
    (void)parentDir;
    (void)directoryId;
#endif
    dir->skipIds = wantIds || (parentDir != NULL && parentDir->skipIds);
    return OpenClassic(dir, pattern, data, fileId);
}

BOOL SnapshotDirNext(SNAPSHOT_DIR* dir, WIN32_FIND_DATA* data, ULONGLONG* fileId)
{
#ifdef UNICODE
    if (dir->ids)
        return ReadIdEntry(dir, data, fileId);
#endif
    *fileId = 0;
    return FindNextFile(dir->find, data);
}

void SnapshotDirClose(SNAPSHOT_DIR* dir)
{
#ifdef UNICODE
    if (dir->ids || dir->directory != INVALID_HANDLE_VALUE || dir->buffer != NULL) {
        CloseIds(dir);
        return;
    }
#endif
    if (dir->find != INVALID_HANDLE_VALUE)
        FindClose(dir->find);
    dir->find = INVALID_HANDLE_VALUE;
}

BOOL SnapshotDirRestartClassic(SNAPSHOT_DIR* dir, LPCTSTR pattern,
    WIN32_FIND_DATA* data, ULONGLONG* fileId)
{
    SnapshotDirClose(dir);
    dir->skipIds = TRUE;
    return OpenClassic(dir, pattern, data, fileId);
}
