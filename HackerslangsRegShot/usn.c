#include "usn.h"
#include <stddef.h>
#include <string.h>

#define USN_BUFFER_SIZE (64 * 1024)

static BOOL QueryJournal(HANDLE volume, USN_JOURNAL_DATA_V0* journal)
{
    DWORD bytes;

    if (!DeviceIoControl(volume, FSCTL_QUERY_USN_JOURNAL, NULL, 0,
            journal, sizeof(*journal), &bytes, NULL))
        return FALSE;
    if (bytes < sizeof(*journal)) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    return TRUE;
}

static BOOL JournalContains(const USN_JOURNAL_DATA_V0* journal,
    ULONGLONG journalId, USN start)
{
    return journal->UsnJournalID == journalId && start >= journal->FirstUsn
        && start >= journal->LowestValidUsn && start <= journal->NextUsn;
}

BOOL UsnReadChanges(HANDLE volume, ULONGLONG journalId, USN start,
    USN_CHANGE_CALLBACK callback, void* context, USN* next)
{
    USN_JOURNAL_DATA_V0 journal;
    READ_USN_JOURNAL_DATA_V0 request;
    BYTE* buffer;
    USN cursor, target;
    BOOL result = FALSE;

    if (callback == NULL || next == NULL || start < 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!QueryJournal(volume, &journal))
        return FALSE;
    if (!JournalContains(&journal, journalId, start)) {
        SetLastError(ERROR_JOURNAL_ENTRY_DELETED);
        return FALSE;
    }

    target = journal.NextUsn;
    cursor = start;
    buffer = HeapAlloc(GetProcessHeap(), 0, USN_BUFFER_SIZE);
    if (buffer == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    ZeroMemory(&request, sizeof(request));
    request.ReasonMask = 0xffffffff;
    request.UsnJournalID = journalId;

    while (cursor < target) {
        DWORD bytes, offset;
        USN returned;

        request.StartUsn = cursor;
        if (!DeviceIoControl(volume, FSCTL_READ_USN_JOURNAL, &request,
                sizeof(request), buffer, USN_BUFFER_SIZE, &bytes, NULL))
            goto done;
        if (bytes < sizeof(returned) || bytes > USN_BUFFER_SIZE) {
            SetLastError(ERROR_INVALID_DATA);
            goto done;
        }
        memcpy(&returned, buffer, sizeof(returned));
        if (returned <= cursor) {
            SetLastError(ERROR_INVALID_DATA);
            goto done;
        }
        offset = sizeof(returned);
        while (offset < bytes) {
            USN_RECORD_V2 record;
            DWORD remaining = bytes - offset;
            DWORD minimum = (DWORD)offsetof(USN_RECORD_V2, FileName);

            if (remaining < minimum) {
                SetLastError(ERROR_INVALID_DATA);
                goto done;
            }
            ZeroMemory(&record, sizeof(record));
            memcpy(&record, buffer + offset, minimum);
            if (record.MajorVersion != 2 || record.RecordLength < minimum
                || record.RecordLength > remaining
                || record.FileNameOffset < minimum
                || record.FileNameOffset > record.RecordLength
                || record.FileNameLength > record.RecordLength - record.FileNameOffset
                || record.Usn < cursor || record.Usn >= returned) {
                SetLastError(ERROR_INVALID_DATA);
                goto done;
            }
            if (record.Usn < target && !callback(record.FileReferenceNumber, context)) {
                SetLastError(ERROR_OPERATION_ABORTED);
                goto done;
            }
            offset += record.RecordLength;
        }
        cursor = returned;
    }

    if (!QueryJournal(volume, &journal))
        goto done;
    if (!JournalContains(&journal, journalId, start) || journal.NextUsn < target) {
        SetLastError(ERROR_JOURNAL_ENTRY_DELETED);
        goto done;
    }
    *next = target;
    result = TRUE;
done:
    {
        DWORD error = GetLastError();
        HeapFree(GetProcessHeap(), 0, buffer);
        if (!result)
            SetLastError(error);
    }
    return result;
}
