#ifndef REGSHOT_FILEENUM_H
#define REGSHOT_FILEENUM_H

#include <windows.h>
#include <tchar.h>

HANDLE FindFirstSnapshotFile(LPCTSTR pattern, WIN32_FIND_DATA* data);

#define SNAPSHOT_VOLUME_GUID_CHARS 64

typedef struct {
    HANDLE find;
    HANDLE directory;
    BYTE* buffer;
    DWORD offset;
    BOOL ids;
    DWORD volumeSerial;
    WCHAR volumeGuid[SNAPSHOT_VOLUME_GUID_CHARS];
} SNAPSHOT_DIR;

/*
 * Pattern must end in \*.*. With wantIds, entries come from
 * FileIdBothDirectoryInfo and include NTFS file IDs; otherwise, or if that
 * is unavailable, FindFirstSnapshotFile is used and *fileId is 0.
 * parentDir, if not NULL, is an ID enumerator of a parent known to be on the
 * same volume (no reparse point in between); its volume GUID is reused when
 * the opened directory has file ID directoryId.
 * Returns FALSE like an invalid find handle; SnapshotDirClose is then not needed.
 */
BOOL SnapshotDirOpen(SNAPSHOT_DIR* dir, LPCTSTR pattern, BOOL wantIds,
    const SNAPSHOT_DIR* parentDir, ULONGLONG directoryId,
    WIN32_FIND_DATA* data, ULONGLONG* fileId);
BOOL SnapshotDirNext(SNAPSHOT_DIR* dir, WIN32_FIND_DATA* data, ULONGLONG* fileId);
void SnapshotDirClose(SNAPSHOT_DIR* dir);

#endif
