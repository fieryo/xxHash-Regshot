#ifndef REGSHOT_USN_H
#define REGSHOT_USN_H

#include <windows.h>
#include <winioctl.h>

typedef struct {
    ULONGLONG fileId;
    ULONGLONG parentId;
    USN usn;
    DWORD reason;
    DWORD attributes;
    const BYTE* name;
    WORD nameBytes;
} USN_CHANGE;

/* The name is UTF-16 bytes and remains valid only during the callback. */
typedef BOOL (*USN_CHANGE_CALLBACK)(const USN_CHANGE* change, void* context);

/* On failure the caller must discard all IDs already passed to callback. */
BOOL UsnReadChanges(HANDLE volume, ULONGLONG journalId, USN start,
    USN_CHANGE_CALLBACK callback, void* context, USN* next);

#endif
