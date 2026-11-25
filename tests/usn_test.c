#include "../xxHash-Regshot/usn.h"
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
    DWORD headerLength = (DWORD)offsetof(USN_RECORD_V2, FileName);
    DWORD length = headerLength + sizeof(WCHAR);
    WCHAR name = L'x';

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
    record.RecordLength = scenario == 4 ? headerLength - 1 : length;
    record.MajorVersion = scenario == 5 ? 3 : 2;
    record.FileReferenceNumber = 42;
    record.ParentFileReferenceNumber = 17;
    record.Usn = scenario == 7 ? 35 : 20;
    record.Reason = USN_REASON_RENAME_NEW_NAME;
    record.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
    record.FileNameOffset = (WORD)headerLength;
    record.FileNameLength = scenario == 8 ? 1 : sizeof(WCHAR);
    memcpy(output, &returned, sizeof(returned));
    memcpy((BYTE*)output + sizeof(returned), &record, headerLength);
    memcpy((BYTE*)output + sizeof(returned) + headerLength, &name, sizeof(name));
    *bytes = sizeof(returned) + length;
    return TRUE;
}

#define DeviceIoControl FakeDeviceIoControl
#include "../xxHash-Regshot/usn.c"

static BOOL SeenFile(const USN_CHANGE* change, void* context)
{
    WCHAR name;
    assert(change->fileId == 42 && change->parentId == 17 && change->usn == 20);
    assert(change->reason == USN_REASON_RENAME_NEW_NAME);
    assert(change->attributes == FILE_ATTRIBUTE_DIRECTORY);
    assert(change->nameBytes == sizeof(name));
    memcpy(&name, change->name, sizeof(name));
    assert(name == L'x');
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

    scenario = 8;
    queryCount = readCount = seen = 0;
    assert(!UsnReadChanges((HANDLE)1, 7, 10, SeenFile, NULL, &next));
    assert(GetLastError() == ERROR_INVALID_DATA && seen == 0);

    puts("USN journal tests passed");
    return 0;
}
