#include "../HackerslangsRegShot/usn.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static int queryCount;
static int readCount;
static int scenario;
static int seen;

static BOOL WINAPI FakeDeviceIoControl(HANDLE volume, DWORD code, LPVOID input,
    DWORD inputSize, LPVOID output, DWORD outputSize, LPDWORD bytes, LPOVERLAPPED overlap)
{
    USN_JOURNAL_DATA_V0 journal;
    USN_RECORD_V2 record;
    USN returned = 30;
    DWORD length = (DWORD)offsetof(USN_RECORD_V2, FileName);

    (void)volume;
    (void)inputSize;
    (void)outputSize;
    (void)overlap;
    if (code == FSCTL_QUERY_USN_JOURNAL) {
        ZeroMemory(&journal, sizeof(journal));
        journal.UsnJournalID = (scenario == 3 && queryCount > 0) ? 9 : 7;
        journal.FirstUsn = scenario == 2 ? 11 : 0;
        journal.LowestValidUsn = 0;
        journal.NextUsn = scenario == 6 ? 10 : 30;
        ++queryCount;
        memcpy(output, &journal, sizeof(journal));
        *bytes = sizeof(journal);
        return TRUE;
    }
    assert(code == FSCTL_READ_USN_JOURNAL);
    assert(((READ_USN_JOURNAL_DATA_V0*)input)->StartUsn == 10);
    ++readCount;
    if (scenario == 7)
        returned = 40;
    ZeroMemory(&record, sizeof(record));
    record.RecordLength = scenario == 4 ? length - 1 : length;
    record.MajorVersion = scenario == 5 ? 3 : 2;
    record.FileReferenceNumber = 42;
    record.Usn = scenario == 7 ? 35 : 20;
    record.FileNameOffset = (WORD)length;
    memcpy(output, &returned, sizeof(returned));
    memcpy((BYTE*)output + sizeof(returned), &record, length);
    *bytes = sizeof(returned) + length;
    return TRUE;
}

#define DeviceIoControl FakeDeviceIoControl
#include "../HackerslangsRegShot/usn.c"

static BOOL SeenFile(ULONGLONG id, void* context)
{
    assert(id == 42);
    ++seen;
    return context == NULL;
}

int main(void)
{
    USN next = -1;

    assert(UsnReadChanges((HANDLE)1, 7, 10, SeenFile, NULL, &next));
    assert(next == 30 && queryCount == 2 && readCount == 1 && seen == 1);

    scenario = 2;
    queryCount = readCount = seen = 0;
    assert(!UsnReadChanges((HANDLE)1, 7, 10, SeenFile, NULL, &next));
    assert(readCount == 0 && GetLastError() == ERROR_JOURNAL_ENTRY_DELETED);

    scenario = 3;
    queryCount = readCount = seen = 0;
    assert(!UsnReadChanges((HANDLE)1, 7, 10, SeenFile, NULL, &next));
    assert(queryCount == 2 && GetLastError() == ERROR_JOURNAL_ENTRY_DELETED);

    scenario = 4;
    queryCount = readCount = seen = 0;
    assert(!UsnReadChanges((HANDLE)1, 7, 10, SeenFile, NULL, &next));
    assert(GetLastError() == ERROR_INVALID_DATA && seen == 0);

    scenario = 5;
    queryCount = readCount = seen = 0;
    assert(!UsnReadChanges((HANDLE)1, 7, 10, SeenFile, NULL, &next));
    assert(GetLastError() == ERROR_INVALID_DATA && seen == 0);

    scenario = 6;
    queryCount = readCount = seen = 0;
    assert(UsnReadChanges((HANDLE)1, 7, 10, SeenFile, NULL, &next));
    assert(next == 10 && queryCount == 2 && readCount == 0 && seen == 0);

    scenario = 0;
    queryCount = readCount = seen = 0;
    assert(!UsnReadChanges((HANDLE)1, 7, 10, SeenFile, &seen, &next));
    assert(GetLastError() == ERROR_OPERATION_ABORTED && seen == 1);

    scenario = 7;
    queryCount = readCount = seen = 0;
    assert(UsnReadChanges((HANDLE)1, 7, 10, SeenFile, NULL, &next));
    assert(next == 30 && readCount == 1 && seen == 0);

    puts("USN journal tests passed");
    return 0;
}
