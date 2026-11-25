#include "../xxHash-Regshot/fileenum.h"
#include <assert.h>
#include <stdio.h>

static DWORD errors[3];
static int successOnCall;
static int calls;
static DWORD lastError;
static FINDEX_INFO_LEVELS levels[3];
static DWORD flags[3];

static HANDLE FakeFindFirstFileEx(LPCTSTR pattern, FINDEX_INFO_LEVELS level,
    LPVOID data, FINDEX_SEARCH_OPS operation, LPVOID filter, DWORD options)
{
    int index = calls++;
    (void)pattern;
    (void)data;
    (void)operation;
    (void)filter;
    levels[index] = level;
    flags[index] = options;
    lastError = errors[index];
    return calls == successOnCall ? (HANDLE)(INT_PTR)1 : INVALID_HANDLE_VALUE;
}

static HANDLE FakeFindFirstFile(LPCTSTR pattern, WIN32_FIND_DATA* data)
{
    int index = calls++;
    (void)pattern;
    (void)data;
    lastError = errors[index];
    return calls == successOnCall ? (HANDLE)(INT_PTR)1 : INVALID_HANDLE_VALUE;
}

static DWORD FakeGetLastError(void) { return lastError; }

#undef FindFirstFileEx
#undef FindFirstFile
#define FindFirstFileEx FakeFindFirstFileEx
#define FindFirstFile FakeFindFirstFile
#define GetLastError FakeGetLastError
#include "../xxHash-Regshot/fileenum.c"

int main(void)
{
    WIN32_FIND_DATA data;

    successOnCall = 1;
    assert(FindFirstSnapshotFile(TEXT("*"), &data) != INVALID_HANDLE_VALUE);
    assert(calls == 1 && levels[0] == FindExInfoBasic && flags[0] == FIND_FIRST_EX_LARGE_FETCH);

    calls = 0;
    successOnCall = 2;
    errors[0] = ERROR_INVALID_PARAMETER;
    assert(FindFirstSnapshotFile(TEXT("*"), &data) != INVALID_HANDLE_VALUE);
    assert(calls == 2 && levels[1] == FindExInfoBasic && flags[1] == 0);

    calls = 0;
    successOnCall = 3;
    errors[0] = ERROR_NOT_SUPPORTED;
    errors[1] = ERROR_INVALID_FUNCTION;
    assert(FindFirstSnapshotFile(TEXT("*"), &data) != INVALID_HANDLE_VALUE);
    assert(calls == 3);

    calls = 0;
    successOnCall = 0;
    errors[0] = ERROR_ACCESS_DENIED;
    assert(FindFirstSnapshotFile(TEXT("*"), &data) == INVALID_HANDLE_VALUE);
    assert(calls == 1 && FakeGetLastError() == ERROR_ACCESS_DENIED);

    calls = 0;
    errors[0] = ERROR_INVALID_PARAMETER;
    errors[1] = ERROR_PATH_NOT_FOUND;
    assert(FindFirstSnapshotFile(TEXT("*"), &data) == INVALID_HANDLE_VALUE);
    assert(calls == 2 && FakeGetLastError() == ERROR_PATH_NOT_FOUND);

    puts("Directory enumeration fallback tests passed");
    return 0;
}
