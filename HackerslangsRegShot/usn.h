#ifndef REGSHOT_USN_H
#define REGSHOT_USN_H

#include <windows.h>
#include <winioctl.h>

typedef BOOL (*USN_CHANGE_CALLBACK)(ULONGLONG fileId, void* context);

/* On failure the caller must discard all IDs already passed to callback. */
BOOL UsnReadChanges(HANDLE volume, ULONGLONG journalId, USN start,
    USN_CHANGE_CALLBACK callback, void* context, USN* next);

#endif
