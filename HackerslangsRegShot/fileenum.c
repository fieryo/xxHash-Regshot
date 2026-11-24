#include "fileenum.h"

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
