#include "../xxHash-Regshot/common.h"

extern size_t nDataBufferSize;
static int valueCalls;
static DWORD firstValueDataSize;
static BOOL keepGrowing;
static int failAllocationAfter = -1;
static BOOL failBulkRead;
static int readCalls;
static TCHAR hivePath[MAX_PATH];
static int loadErrors;
static BOOL failHiveWrite;
static BOOL retryValue;
static int registryMode;
static HKEY registryRoot, queryDeniedKey;
static int keyCalls;
static BOOL keepKeyGrowing;
static size_t nameComparisons;
static BOOL profileRegistry;
static BOOL profileLegacyCapacity;
static BOOL countFileAllocations;
static size_t fileAllocations;
static ULONGLONG profileDataBytes;
static DWORD profileMaxDataCapacity;
typedef struct {
    ULONGLONG calls;
    LONGLONG ticks;
} REGISTRY_PROFILE;
static REGISTRY_PROFILE profileOpen, profileClose, profileInfo, profileValues, profileKeys, profileAlloc;

#define PROFILE_REGISTRY_RETURN(profile, call) do { \
    LARGE_INTEGER start, end; \
    LONG profileResult; \
    if (!profileRegistry) \
        return (call); \
    QueryPerformanceCounter(&start); \
    profileResult = (call); \
    QueryPerformanceCounter(&end); \
    ++(profile).calls; \
    (profile).ticks += end.QuadPart - start.QuadPart; \
    return profileResult; \
} while (0)

static int CountNameCompare(LPCTSTR left, LPCTSTR right)
{
    ++nameComparisons;
    return _tcsicmp(left, right);
}

static LPVOID WINAPI FakeHeapAlloc(HANDLE heap, DWORD flags, SIZE_T size)
{
    LARGE_INTEGER start, end;
    LPVOID result;

    if (countFileAllocations)
        ++fileAllocations;
    if (failAllocationAfter == 0)
        return NULL;
    if (failAllocationAfter > 0)
        --failAllocationAfter;
    if (!profileRegistry)
        return HeapAlloc(heap, flags, size);
    QueryPerformanceCounter(&start);
    result = HeapAlloc(heap, flags, size);
    QueryPerformanceCounter(&end);
    ++profileAlloc.calls;
    profileAlloc.ticks += end.QuadPart - start.QuadPart;
    return result;
}

static BOOL WINAPI FakeReadFile(HANDLE file, LPVOID data, DWORD size, LPDWORD read, LPOVERLAPPED overlapped)
{
    if (failBulkRead && ++readCalls == 2) {
        *read = 0;
        SetLastError(ERROR_READ_FAULT);
        return FALSE;
    }
    return ReadFile(file, data, size, read, overlapped);
}

static BOOL WINAPI FakeWriteFile(HANDLE file, LPCVOID data, DWORD size, LPDWORD written, LPOVERLAPPED overlapped)
{
    if (failHiveWrite) {
        *written = 0;
        SetLastError(ERROR_DISK_FULL);
        return FALSE;
    }
    return WriteFile(file, data, size, written, overlapped);
}

static BOOL WINAPI FakeOpenFileName(LPOPENFILENAME dialog)
{
    _tcscpy_s(dialog->lpstrFile, dialog->nMaxFile, hivePath);
    dialog->nFileOffset = (WORD)(_tcsrchr(dialog->lpstrFile, (TCHAR)'\\') - dialog->lpstrFile + 1);
    return TRUE;
}

static VOID FakeErrMsg(LPTSTR text)
{
    assert(text != NULL);
    ++loadErrors;
}
static LONG WINAPI FakeRegEnumValue(HKEY key, DWORD index, LPTSTR name, LPDWORD length,
    LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD size)
{
    (void)key;
    (void)reserved;
    if (!retryValue) {
        if (profileRegistry) {
            if (profileLegacyCapacity)
                *size = (DWORD)nDataBufferSize;
            profileDataBytes += *size;
            if (*size > profileMaxDataCapacity)
                profileMaxDataCapacity = *size;
        }
        PROFILE_REGISTRY_RETURN(profileValues,
            RegEnumValue(key, index, name, length, reserved, type, data, size));
    }
    assert(index == 7);
    if (++valueCalls == 1)
        firstValueDataSize = *size;
    if (valueCalls == 1 || keepGrowing) {
        *size = 4096;
        return ERROR_MORE_DATA;
    }
    assert(*length >= 2 && *size >= 4096);
    _tcscpy_s(name, *length, TEXT("v"));
    *length = 1;
    data[0] = 0x42;
    *size = 1;
    *type = REG_BINARY;
    return ERROR_SUCCESS;
}

static LONG WINAPI FakeRegOpenKeyEx(HKEY key, LPCTSTR name, DWORD options, REGSAM access, PHKEY result)
{
    LONG error;

    if (registryMode == 1 && _tcscmp(name, TEXT("DRIVERS")) == 0)
        return ERROR_ACCESS_DENIED;
    if (profileRegistry) {
        PROFILE_REGISTRY_RETURN(profileOpen, RegOpenKeyEx(key, name, options, access, result));
    }
    error = RegOpenKeyEx(key, name, options, access, result);
    if (registryMode == 2 && error == ERROR_SUCCESS && _tcscmp(name, TEXT("DRIVERS")) == 0)
        queryDeniedKey = *result;
    return error;
}

static LONG WINAPI FakeRegQueryInfoKey(HKEY key, LPTSTR className, LPDWORD classLength,
    LPDWORD reserved, LPDWORD subKeys, LPDWORD maxSubKey, LPDWORD maxClass,
    LPDWORD values, LPDWORD maxValueName, LPDWORD maxData, LPDWORD security, PFILETIME writeTime)
{
    if (registryMode == 2 && key == queryDeniedKey) {
        queryDeniedKey = NULL;
        return ERROR_ACCESS_DENIED;
    }
    PROFILE_REGISTRY_RETURN(profileInfo,
        RegQueryInfoKey(key, className, classLength, reserved, subKeys, maxSubKey, maxClass,
            values, maxValueName, maxData, security, writeTime));
}

static LONG WINAPI FakeRegEnumKeyEx(HKEY key, DWORD index, LPTSTR name, LPDWORD length,
    LPDWORD reserved, LPTSTR className, LPDWORD classLength, PFILETIME writeTime)
{
    if (registryMode == 3 && key == registryRoot && index == 1)
        return ERROR_ACCESS_DENIED;
    if (registryMode == 4) {
        assert(index == 7);
        ++keyCalls;
        if (keyCalls == 1 || keepKeyGrowing)
            return ERROR_MORE_DATA;
        _tcscpy_s(name, *length, TEXT("long-key"));
        *length = 8;
        return ERROR_SUCCESS;
    }
    PROFILE_REGISTRY_RETURN(profileKeys,
        RegEnumKeyEx(key, index, name, length, reserved, className, classLength, writeTime));
}

static LONG WINAPI ProfileRegCloseKey(HKEY key)
{
    PROFILE_REGISTRY_RETURN(profileClose, RegCloseKey(key));
}

#undef RegEnumValue
#define RegEnumValue FakeRegEnumValue
#undef RegEnumKeyEx
#define RegEnumKeyEx FakeRegEnumKeyEx
#undef RegOpenKeyEx
#define RegOpenKeyEx FakeRegOpenKeyEx
#undef RegQueryInfoKey
#define RegQueryInfoKey FakeRegQueryInfoKey
#define RegCloseKey ProfileRegCloseKey
#undef _tcsicmp
#define _tcsicmp CountNameCompare
#undef GetOpenFileName
#define GetOpenFileName FakeOpenFileName
#undef GetSaveFileName
#define GetSaveFileName FakeOpenFileName
#define HeapAlloc FakeHeapAlloc
#define ReadFile FakeReadFile
#define WriteFile FakeWriteFile
#define ErrMsg FakeErrMsg
#include "../xxHash-Regshot/regshot.c"
#include "../xxHash-Regshot/usnsnapshot.c"
#include "../xxHash-Regshot/fileenum.h"
#include "../xxHash-Regshot/checksum.h"

static int enumerationMode;
static int classicRestarts;
static int directoryOpens;
static int hashCalls, reuseCalls, idRequests;
static BOOL offerCachedHash;

static BOOL CountChecksumFromFile(LPCTSTR path, QWORD* checksum)
{
    ++hashCalls;
    return ChecksumFromFile(path, checksum);
}

static CHECKSUM_RESULT CountChecksumTextFile(LPCTSTR path, QWORD* checksum)
{
    ++hashCalls;
    return ChecksumTextFile(path, checksum);
}

static BOOL FakeReuseHash(const USN_SNAPSHOT* snapshot, DWORD volume, ULONGLONG fileId,
    ULONGLONG size, ULONGLONG writeTime, DWORD attributes, ULONGLONG* hash)
{
    ++reuseCalls;
    if (offerCachedHash) {
        *hash = 0x1234;
        return TRUE;
    }
    return UsnSnapshotReuseHash(snapshot, volume, fileId, size, writeTime, attributes, hash);
}

static BOOL FakeSnapshotDirOpen(SNAPSHOT_DIR* dir, LPCTSTR pattern, BOOL wantIds,
    const SNAPSHOT_DIR* parent, ULONGLONG directoryId, WIN32_FIND_DATA* data, ULONGLONG* id)
{
    ++directoryOpens;
    if (wantIds)
        ++idRequests;
    if (enumerationMode == 3 || enumerationMode == 5) {
        SetLastError(enumerationMode == 3 ? ERROR_ACCESS_DENIED : ERROR_READ_FAULT);
        return FALSE;
    }
    if (enumerationMode == 4) {
        ZeroMemory(dir, sizeof(*dir));
        dir->find = dir->directory = INVALID_HANDLE_VALUE;
        ZeroMemory(data, sizeof(*data));
        _tcscpy_s(data->cFileName, MAX_PATH, TEXT("loop"));
        data->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT;
        *id = 0;
        return TRUE;
    }
    if (enumerationMode == 7) {
        assert(wantIds);
        ZeroMemory(dir, sizeof(*dir));
        dir->find = dir->directory = INVALID_HANDLE_VALUE;
        dir->ids = TRUE;
        ZeroMemory(data, sizeof(*data));
        _tcscpy_s(data->cFileName, MAX_PATH, TEXT("file"));
        data->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
        data->nFileSizeLow = 2;
        *id = 123;
        return TRUE;
    }
    if (enumerationMode == 1 && wantIds) {
        ZeroMemory(dir, sizeof(*dir));
        dir->find = dir->directory = INVALID_HANDLE_VALUE;
        dir->ids = TRUE;
        ZeroMemory(data, sizeof(*data));
        _tcscpy_s(data->cFileName, MAX_PATH, TEXT("first"));
        data->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
        *id = 123;
        return TRUE;
    }
    if (enumerationMode == 1)
        ++classicRestarts;
    return SnapshotDirOpen(dir, pattern, wantIds, parent, directoryId, data, id);
}

static BOOL FakeSnapshotDirNext(SNAPSHOT_DIR* dir, WIN32_FIND_DATA* data, ULONGLONG* id)
{
    if (enumerationMode == 4 || enumerationMode == 7) {
        SetLastError(ERROR_NO_MORE_FILES);
        return FALSE;
    }
    if ((enumerationMode == 1 && dir->ids) || enumerationMode == 2 || enumerationMode == 6) {
        SetLastError(enumerationMode == 6 ? ERROR_ACCESS_DENIED : ERROR_READ_FAULT);
        return FALSE;
    }
    return SnapshotDirNext(dir, data, id);
}

static DWORD FakeSnapshotVolume(USN_SNAPSHOT* snapshot, const WCHAR* guid, DWORD serial)
{
    return enumerationMode == 1 || enumerationMode == 7 ? 1 : UsnSnapshotVolume(snapshot, guid, serial);
}

#define ChecksumFromFile CountChecksumFromFile
#define ChecksumTextFile CountChecksumTextFile
#define UsnSnapshotReuseHash FakeReuseHash
#define SnapshotDirOpen FakeSnapshotDirOpen
#define SnapshotDirNext FakeSnapshotDirNext
#define UsnSnapshotVolume FakeSnapshotVolume
#include "../xxHash-Regshot/fileshot.c"
#undef SnapshotDirOpen
#undef SnapshotDirNext
#undef UsnSnapshotVolume
#undef ChecksumFromFile
#undef ChecksumTextFile
#undef UsnSnapshotReuseHash

static void TestRegistryFormatting(void)
{
    BYTE bytes[] = { 0x12, 0x34, 0x56 };
    VALUECONTENT value = { 0 };
    LPTSTR result;
    TCHAR strings[2402];
    size_t i;

    value.lpValueData = bytes;
    value.cbData = sizeof(bytes);
    result = TransData(&value, REG_BINARY, FALSE);
    assert(_tcscmp(result, TEXT(": 12 34 56")) == 0);
    MYFREE(result);
    value.cbData = 1;
    result = TransData(&value, REG_BINARY, FALSE);
    assert(_tcscmp(result, TEXT(": 12")) == 0);
    MYFREE(result);

    for (i = 0; i < 1200; ++i) {
        strings[2 * i] = (TCHAR)'x';
        strings[2 * i + 1] = 0;
    }
    strings[2400] = strings[2401] = 0;
    value.lpValueData = (LPBYTE)strings;
    value.cbData = sizeof(strings);
    result = TransData(&value, REG_MULTI_SZ, FALSE);
    assert(_tcslen(result) == 6000);
    assert(_tcsncmp(result, TEXT(": \"x\", \"x\""), 10) == 0);
    assert(result[5999] == (TCHAR)'"');
    MYFREE(result);

    strings[0] = (TCHAR)'x';
    strings[1] = (TCHAR)'y';
    value.cbData = 2 * sizeof(TCHAR);
    result = TransData(&value, REG_SZ, FALSE);
    assert(_tcscmp(result, TEXT(": \"xy\"")) == 0);
    MYFREE(result);
}

static void TestHtmlReportEncoding(void)
{
    TCHAR directory[MAX_PATH], path[MAX_PATH];
    WCHAR report[4096];
    DWORD size, read;

    assert(GetTempPath(MAX_PATH, directory) && GetTempFileName(directory, TEXT("rs"), 0, path));
    hFile = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    assert(hFile != INVALID_HANDLE_VALUE);
    assert(WriteHTMLBegin());
    WriteTitle(TEXT("Comments:"), TEXT("Caf\x00e9 \x03a9"), TRUE);
    WriteHTMLEnd();
    assert(CloseHandle(hFile));
    hFile = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    assert(hFile != INVALID_HANDLE_VALUE);
    size = GetFileSize(hFile, NULL);
    assert(size > 2 && size < sizeof(report) && size % sizeof(WCHAR) == 0);
    assert(ReadFile(hFile, report, size, &read, NULL) && read == size);
    report[size / sizeof(WCHAR)] = L'\0';
    assert(report[0] == 0xfeff);
    assert(wcsncmp(report + 1, L"<HTML>\r\n<HEAD>\r\n", 16) == 0);
    assert(wcsstr(report, L"charset=utf-16") != NULL);
    assert(wcsstr(report, L"Caf\x00e9 \x03a9") != NULL);
    assert(wcsstr(report, L"</BODY>\r\n</HTML>\r\n") != NULL);
    assert(!WriteHTMLBegin());
    assert(CloseHandle(hFile));
    hFile = INVALID_HANDLE_VALUE;
    assert(DeleteFile(path));
}

static void TestValueRetry(void)
{
    DWORD nameLength, type, dataLength;

    retryValue = TRUE;
    nStringBufferSize = sizeof(TCHAR);
    lpStringBuffer = MYALLOC(nStringBufferSize);
    // A large buffer left over from an earlier key must not be advertised.
    nDataBufferSize = 1024 * 1024;
    lpDataBuffer = MYALLOC(nDataBufferSize);
    assert(EnumerateSnapshotValue(NULL, 7, 16, &nameLength, &type, &dataLength) == ERROR_SUCCESS);
    assert(firstValueDataSize == 16);
    assert(valueCalls == 2 && nameLength == 1 && dataLength == 1 && lpDataBuffer[0] == 0x42);
    valueCalls = 0;
    keepGrowing = TRUE;
    assert(EnumerateSnapshotValue(NULL, 7, 0, &nameLength, &type, &dataLength) == ERROR_MORE_DATA);
    assert(valueCalls == 9);
    MYFREE(lpStringBuffer);
    MYFREE(lpDataBuffer);
    lpStringBuffer = NULL;
    lpDataBuffer = NULL;
    retryValue = FALSE;
}

static void TestKeyRetry(void)
{
    DWORD length;

    registryMode = 4;
    nStringBufferSize = sizeof(TCHAR);
    lpStringBuffer = MYALLOC(nStringBufferSize);
    assert(EnumerateSnapshotKey(NULL, 7, &length) == ERROR_SUCCESS);
    assert(keyCalls == 2 && length == 8);
    keyCalls = 0;
    keepKeyGrowing = TRUE;
    assert(EnumerateSnapshotKey(NULL, 7, &length) == ERROR_MORE_DATA);
    assert(keyCalls == 9);
    MYFREE(lpStringBuffer);
    lpStringBuffer = NULL;
    registryMode = 0;
}

static void TestRegistryAvailability(void)
{
    TCHAR temp[MAX_PATH], unique[MAX_PATH], path[MAX_PATH];
    HKEY drivers, child, visible;
    REGSHOT before = { 0 }, after = { 0 };
    DWORD data = 1;
    int mode;

    assert(GetTempPath(MAX_PATH, temp) && GetTempFileName(temp, TEXT("rs"), 0, unique));
    assert(DeleteFile(unique));
    _tcscpy_s(path, _countof(path), TEXT("Software\\RegshotTest-"));
    _tcscat_s(path, _countof(path), _tcsrchr(unique, (TCHAR)'\\') + 1);
    assert(RegCreateKeyEx(HKEY_CURRENT_USER, path, 0, NULL, 0, KEY_ALL_ACCESS, NULL,
        &registryRoot, NULL) == ERROR_SUCCESS);
    assert(RegCreateKeyEx(registryRoot, TEXT("DRIVERS"), 0, NULL, 0, KEY_ALL_ACCESS, NULL,
        &drivers, NULL) == ERROR_SUCCESS);
    assert(RegCreateKeyEx(drivers, TEXT("DriverDatabase"), 0, NULL, 0, KEY_ALL_ACCESS, NULL,
        &child, NULL) == ERROR_SUCCESS);
    RegCloseKey(child);
    assert(RegSetValueEx(drivers, TEXT("value"), 0, REG_DWORD, (const BYTE*)&data, sizeof(data)) == ERROR_SUCCESS);
    assert(RegCreateKeyEx(registryRoot, TEXT("Visible"), 0, NULL, 0, KEY_ALL_ACCESS, NULL,
        &visible, NULL) == ERROR_SUCCESS);
    assert(RegSetValueEx(visible, TEXT("value"), 0, REG_DWORD, (const BYTE*)&data, sizeof(data)) == ERROR_SUCCESS);
    GetRegistrySnap(&before, registryRoot, lpszHKLMShort, NULL, &before.lpHKLM);
    assert(before.stCounts.cKeys == 4 && before.stCounts.cValues == 2 && before.cSkippedRegKeys == 0);
    data = 2;
    assert(RegSetValueEx(visible, TEXT("value"), 0, REG_DWORD, (const BYTE*)&data, sizeof(data)) == ERROR_SUCCESS);

    for (mode = 1; mode <= 3; ++mode) {
        registryMode = mode;
        queryDeniedKey = NULL;
        GetRegistrySnap(&after, registryRoot, lpszHKLMShort, NULL, &after.lpHKLM);
        registryMode = 0;
        assert(!after.fIncomplete && after.cSkippedRegKeys == 1);
        MYFREE(lpStringBuffer);
        MYFREE(lpDataBuffer);
        lpStringBuffer = NULL;
        lpDataBuffer = NULL;
        after.fFilled = TRUE;
        after.stCounts.cAll = after.stCounts.cKeys + after.stCounts.cValues;
        assert(GetTempFileName(temp, TEXT("rs"), 0, hivePath));
        SaveShot(&after);
        assert(!fHiveWriteFailed);
        FreeShot(&after);
        assert(LoadShot(&after));
        assert(after.cSkippedRegKeys == 1);
        assert(DeleteFile(hivePath));

        CompareRegKeys(before.lpHKLM, after.lpHKLM);
        assert(CompareResult.stcAdded.cKeys == 0 && CompareResult.stcDeleted.cKeys == 0);
        assert(CompareResult.stcAdded.cValues == 0 && CompareResult.stcDeleted.cValues == 0);
        assert(CompareResult.stcModified.cValues == (mode == 3 ? 0 : 1));
        FreeCompareResult();
        ClearRegKeyMatchFlags(before.lpHKLM);
        ClearRegKeyMatchFlags(after.lpHKLM);
        CompareRegKeys(after.lpHKLM, before.lpHKLM);
        assert(CompareResult.stcAdded.cKeys == 0 && CompareResult.stcDeleted.cKeys == 0);
        assert(CompareResult.stcAdded.cValues == 0 && CompareResult.stcDeleted.cValues == 0);
        assert(CompareResult.stcModified.cValues == (mode == 3 ? 0 : 1));
        FreeCompareResult();
        ClearRegKeyMatchFlags(before.lpHKLM);
        FreeShot(&after);
    }
    assert(RegDeleteKey(drivers, TEXT("DriverDatabase")) == ERROR_SUCCESS);
    RegCloseKey(drivers);
    RegCloseKey(visible);
    assert(RegDeleteKey(registryRoot, TEXT("DRIVERS")) == ERROR_SUCCESS);
    assert(RegDeleteKey(registryRoot, TEXT("Visible")) == ERROR_SUCCESS);
    GetRegistrySnap(&after, registryRoot, lpszHKLMShort, NULL, &after.lpHKLM);
    CompareRegKeys(before.lpHKLM, after.lpHKLM);
    assert(CompareResult.stcDeleted.cKeys == 3 && CompareResult.stcDeleted.cValues == 2);
    FreeCompareResult();
    FreeShot(&before);
    FreeShot(&after);
    RegCloseKey(registryRoot);
    assert(RegDeleteKey(HKEY_CURRENT_USER, path) == ERROR_SUCCESS);
    MYFREE(lpStringBuffer);
    MYFREE(lpDataBuffer);
    lpStringBuffer = NULL;
    lpDataBuffer = NULL;
}

static void TestIndexedComparison(void)
{
    const size_t count = 4096;
    LPKEYCONTENT keys1 = MYALLOC0(count * sizeof(*keys1)), keys2 = MYALLOC0(count * sizeof(*keys2));
    LPVALUECONTENT values1 = MYALLOC0(count * sizeof(*values1)), values2 = MYALLOC0(count * sizeof(*values2));
    LPFILECONTENT files1 = MYALLOC0(count * sizeof(*files1)), files2 = MYALLOC0(count * sizeof(*files2));
    TCHAR (*names)[32] = MYALLOC(count * sizeof(*names));
    size_t i;

    assert(keys1 && keys2 && values1 && values2 && files1 && files2 && names);
    for (i = 0; i < count; ++i)
        _sntprintf_s(names[i], 32, _TRUNCATE, TEXT("item%05u"), (unsigned)i);
    for (i = 0; i < count; ++i) {
        keys1[i].lpszKeyName = values1[i].lpszValueName = files1[i].lpszFileName = names[i];
        keys2[i].lpszKeyName = values2[i].lpszValueName = files2[i].lpszFileName = names[count - i - 1];
        values1[i].nTypeCode = values2[i].nTypeCode = REG_DWORD;
        files1[i].nFileAttributes = files2[i].nFileAttributes = FILE_ATTRIBUTE_NORMAL;
        if (i + 1 < count) {
            keys1[i].lpBrotherKC = &keys1[i + 1];
            keys2[i].lpBrotherKC = &keys2[i + 1];
            values1[i].lpBrotherVC = &values1[i + 1];
            values2[i].lpBrotherVC = &values2[i + 1];
            files1[i].lpBrotherFC = &files1[i + 1];
            files2[i].lpBrotherFC = &files2[i + 1];
        }
    }
    keys2[count - 1].lpszKeyName = TEXT("ITEM00000");
    values1[0].lpszValueName = values2[count - 1].lpszValueName = NULL;
    keys1[0].lpFirstVC = values1;
    keys2[count - 1].lpFirstVC = values2;
    nameComparisons = 0;
    CompareRegKeys(keys1, keys2);
    assert(CompareResult.stcChanged.cKeys == 0 && CompareResult.stcChanged.cValues == 0);
    assert(CompareResult.stcCompared.cKeys == count && CompareResult.stcCompared.cValues == count);
    assert(nameComparisons < count * 100);
    ClearRegKeyMatchFlags(keys2);
    FreeCompareResult();
    values2[0].nTypeCode = REG_BINARY;
    values2[1].cbData = 1;
    values2[1].lpValueData = (LPBYTE)"x";
    keys2[0].lpszKeyName = TEXT("renamed");
    CompareRegKeys(keys1, keys2);
    assert(CompareResult.stcAdded.cKeys == 1 && CompareResult.stcDeleted.cKeys == 1);
    assert(CompareResult.stcAdded.cValues == 1 && CompareResult.stcDeleted.cValues == 1);
    assert(CompareResult.stcModified.cValues == 1);
    FreeCompareResult();

    nameComparisons = 0;
    CompareFiles(files1, files2);
    assert(CompareResult.stcChanged.cFiles == 0 && CompareResult.stcCompared.cFiles == count);
    assert(nameComparisons < count * 100);
    ClearFileMatchFlags(files2);
    FreeCompareResult();
    files2[0].nChkSum = 1;
    files2[1].nFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
    files2[2].lpszFileName = TEXT("renamed");
    CompareFiles(files1, files2);
    assert(CompareResult.stcAdded.cFiles == 1 && CompareResult.stcDeleted.cFiles == 2);
    assert(CompareResult.stcModified.cFiles == 1 && CompareResult.stcAdded.cDirs == 1);
    FreeCompareResult();
    ClearFileMatchFlags(files2);
    files1[2].lpBrotherFC = NULL;
    // A failed index allocation must preserve the sequential comparison result.
    failAllocationAfter = 0;
    CompareFiles(files1, &files2[count - 3]);
    failAllocationAfter = -1;
    assert(CompareResult.stcChanged.cFiles == 0 && CompareResult.stcCompared.cFiles == 3);
    FreeCompareResult();
    MYFREE(keys1);
    MYFREE(keys2);
    MYFREE(values1);
    MYFREE(values2);
    MYFREE(files1);
    MYFREE(files2);
    MYFREE(names);
}

static void TestHiveValidation(void)
{
    BYTE data[512] = { 0 };
    FILEHEADER header = { 0 };
    SAVEHEADFILE head = { 0 };
    SAVEFILECONTENT file = { 0 };
    SAVEKEYCONTENT key = { 0 };
    SAVEVALUECONTENT value = { 0 };
    const WCHAR name[] = L"x";
    DWORD fileOffset = sizeof(header) + sizeof(head);
    DWORD nameOffset = fileOffset + sizeof(file);

    header.nFHSize = sizeof(header);
    header.nFHVersion = FILEHEADER_VERSION_CURRENT;
    header.nCharSize = sizeof(WCHAR);
    header.nKCVersion = KEYCONTENT_VERSION_CURRENT;
    header.nKCSize = sizeof(key);
    header.nVCVersion = VALUECONTENT_VERSION_CURRENT;
    header.nVCSize = sizeof(value);
    header.nHFVersion = HEADFILE_VERSION_CURRENT;
    header.nHFSize = sizeof(head);
    header.nFCVersion = FILECONTENT_VERSION_CURRENT;
    header.nFCSize = sizeof(file);
    header.ofsHF = sizeof(header);
    head.ofsFirstFileContent = fileOffset;
    file.ofsFileName = nameOffset;
    file.nFileNameLen = 2;
    memcpy(data + sizeof(header), &head, sizeof(head));
    memcpy(data + fileOffset, &file, sizeof(file));
    memcpy(data + nameOffset, name, sizeof(name));
    assert(ValidateHive(data, nameOffset + sizeof(name), &header));
    header.nFCVersion = FILECONTENT_VERSION_3;
    header.nFCSize = offsetof(SAVEFILECONTENT, nScanError);
    assert(ValidateHive(data, nameOffset + sizeof(name), &header));
    header.nFCVersion = FILECONTENT_VERSION_CURRENT;
    header.nFCSize = sizeof(file);
    file.nScanError = ERROR_ACCESS_DENIED;
    memcpy(data + fileOffset, &file, sizeof(file));
    assert(!ValidateHive(data, sizeof(data), &header));
    file.nFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
    memcpy(data + fileOffset, &file, sizeof(file));
    assert(ValidateHive(data, sizeof(data), &header));
    file.nScanError = 0;
    memcpy(data + fileOffset, &file, sizeof(file));
    assert(!ValidateHive(data, nameOffset + sizeof(name) - 1, &header));
    file.ofsBrotherFile = fileOffset;
    memcpy(data + fileOffset, &file, sizeof(file));
    assert(!ValidateHive(data, sizeof(data), &header));
    file.ofsBrotherFile = 0;
    file.nFileNameLen = MAXDWORD;
    memcpy(data + fileOffset, &file, sizeof(file));
    assert(!ValidateHive(data, sizeof(data), &header));
    file.nFileNameLen = 2;
    file.ofsFileName = sizeof(data) - 1;
    memcpy(data + fileOffset, &file, sizeof(file));
    assert(!ValidateHive(data, sizeof(data), &header));

    header.ofsHF = 0;
    header.ofsHKLM = sizeof(header);
    key.ofsKeyName = sizeof(header) + sizeof(key) + sizeof(value);
    key.nKeyNameLen = 2;
    key.ofsFirstValue = sizeof(header) + sizeof(key);
    value.cbData = 2;
    value.ofsValueData = key.ofsKeyName;
    memcpy(data + header.ofsHKLM, &key, sizeof(key));
    memcpy(data + key.ofsFirstValue, &value, sizeof(value));
    memcpy(data + key.ofsKeyName, name, sizeof(name));
    assert(ValidateHive(data, sizeof(data), &header));
    header.nKCVersion = KEYCONTENT_VERSION_2;
    header.nKCSize = offsetof(SAVEKEYCONTENT, nScanError);
    assert(ValidateHive(data, sizeof(data), &header));
    header.nKCVersion = KEYCONTENT_VERSION_CURRENT;
    header.nKCSize = sizeof(key);
    value.ofsValueData = sizeof(data) - 1;
    memcpy(data + key.ofsFirstValue, &value, sizeof(value));
    assert(!ValidateHive(data, sizeof(data), &header));
    value.ofsValueData = key.ofsKeyName;
    value.ofsBrotherValue = key.ofsFirstValue;
    memcpy(data + key.ofsFirstValue, &value, sizeof(value));
    assert(!ValidateHive(data, sizeof(data), &header));
    key.ofsFirstSubKey = header.ofsHKLM;
    key.ofsFirstValue = 0;
    memcpy(data + header.ofsHKLM, &key, sizeof(key));
    assert(!ValidateHive(data, sizeof(data), &header));
}

static void TestLoadFailures(void)
{
    BYTE data[512] = { 0 };
    FILEHEADER header = { 0 };
    SAVEKEYCONTENT key = { 0 };
    SAVEVALUECONTENT value = { 0 };
    SAVEHEADFILE head = { 0 };
    SAVEFILECONTENT file = { 0 };
    const WCHAR keyName[] = L"HKLM", name[] = L"x";
    TCHAR temp[MAX_PATH];
    HANDLE disk;
    DWORD written;
    REGSHOT shot = { 0 };
    int failure;

    memcpy(header.signature, "REGSHOTHIV2", 11);
    header.nFHSize = sizeof(header);
    header.nFHVersion = FILEHEADER_VERSION_CURRENT;
    header.nCharSize = sizeof(WCHAR);
    header.nEndianness = FILEHEADER_ENDIANNESS_VALUE;
    header.nKCVersion = KEYCONTENT_VERSION_CURRENT;
    header.nKCSize = sizeof(key);
    header.nVCVersion = VALUECONTENT_VERSION_CURRENT;
    header.nVCSize = sizeof(value);
    header.nHFVersion = HEADFILE_VERSION_CURRENT;
    header.nHFSize = sizeof(head);
    header.nFCVersion = FILECONTENT_VERSION_CURRENT;
    header.nFCSize = sizeof(file);
    header.ofsHKLM = sizeof(header);
    key.ofsKeyName = 260;
    key.nKeyNameLen = _countof(keyName);
    key.ofsFirstValue = 280;
    value.ofsValueName = 310;
    value.nValueNameLen = _countof(name);
    value.ofsValueData = 316;
    value.cbData = 2;
    value.nTypeCode = REG_BINARY;
    header.ofsHF = 320;
    head.ofsFirstFileContent = 328;
    file.ofsFileName = 400;
    file.nFileNameLen = _countof(name);
    memcpy(data, &header, sizeof(header));
    memcpy(data + header.ofsHKLM, &key, sizeof(key));
    memcpy(data + key.ofsKeyName, keyName, sizeof(keyName));
    memcpy(data + key.ofsFirstValue, &value, sizeof(value));
    memcpy(data + value.ofsValueName, name, sizeof(name));
    memcpy(data + header.ofsHF, &head, sizeof(head));
    memcpy(data + head.ofsFirstFileContent, &file, sizeof(file));
    memcpy(data + file.ofsFileName, name, sizeof(name));
    assert(ValidateHive(data, sizeof(data), &header));
    assert(GetTempPath(MAX_PATH, temp) && GetTempFileName(temp, TEXT("rs"), 0, hivePath));
    disk = CreateFile(hivePath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    assert(disk != INVALID_HANDLE_VALUE && WriteFile(disk, data, sizeof(data), &written, NULL));
    CloseHandle(disk);
    shot.fFilled = TRUE;
    shot.lpszComputerName = MYALLOC(8 * sizeof(TCHAR));
    _tcscpy_s(shot.lpszComputerName, 8, TEXT("old"));
    // File buffer, key/name/value/data buffers, head and file/name nodes.
    for (failure = 0; failure < 10; ++failure) {
        printf("Testing load allocation failure %d\n", failure);
        failAllocationAfter = failure;
        assert(!LoadShot(&shot));
        failAllocationAfter = -1;
        assert(shot.fFilled && _tcscmp(shot.lpszComputerName, TEXT("old")) == 0);
        assert(lpFileBuffer == NULL && lpStringBuffer == NULL);
    }
    assert(loadErrors == 10);
    failBulkRead = TRUE;
    readCalls = 0;
    assert(!LoadShot(&shot));
    assert(lpFileBuffer == NULL && _tcscmp(shot.lpszComputerName, TEXT("old")) == 0);
    failBulkRead = FALSE;
    assert(LoadShot(&shot));
    assert(shot.fFilled && shot.fLoaded && shot.stCounts.cKeys == 1
        && shot.stCounts.cValues == 1 && shot.stCounts.cFiles == 1);
    FreeShot(&shot);
    assert(DeleteFile(hivePath));
}

static void TestPathTrimming(void)
{
    TCHAR one[] = TEXT("x\\ ");
    TCHAR empty[] = TEXT(" \\");
    TCHAR root[] = TEXT("C:\\");

    assert(TrimSnapshotPath(one) && _tcscmp(one, TEXT("x")) == 0);
    assert(!TrimSnapshotPath(empty));
    assert(TrimSnapshotPath(root) && _tcscmp(root, TEXT("C:")) == 0);
}

static void TestMetadataOnly(void)
{
    TCHAR temp[MAX_PATH], path[MAX_PATH], filePath[MAX_PATH];
    REGSHOT shot = { 0 };
    USN_SNAPSHOT snapshot = { 0 };
    HANDLE file;
    DWORD written;
    FILECONTENT before, after;

    assert(GetTempPath(MAX_PATH, temp) && GetTempFileName(temp, TEXT("rs"), 0, path));
    assert(DeleteFile(path) && CreateDirectory(path, NULL));
    _tcscpy_s(filePath, _countof(filePath), path);
    _tcscat_s(filePath, _countof(filePath), TEXT("\\file"));
    file = CreateFile(filePath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    assert(file != INVALID_HANDLE_VALUE);
    assert(WriteFile(file, "hi", 2, &written, NULL) && written == 2);
    CloseHandle(file);
    hashCalls = reuseCalls = idRequests = 0;
    offerCachedHash = TRUE;
    enumerationMode = 7;
    shot.lpHF = MYALLOC0(sizeof(HEADFILE));
    shot.lpUsnSnapshot = &snapshot;
    GetFilesSnap(&shot, path, NULL, &shot.lpHF->lpFirstFC, NULL);
    assert(!shot.fIncomplete && reuseCalls == 1 && hashCalls == 0);
    assert(shot.lpHF->lpFirstFC->lpFirstSubFC->nChkSum == 0x1234);
    shot.lpUsnSnapshot = NULL;
    FreeShot(&shot);

    shot.lpHF = MYALLOC0(sizeof(HEADFILE));
    shot.lpUsnSnapshot = &snapshot;
    shot.fTextOnly = TRUE;
    hashCalls = reuseCalls = 0;
    GetFilesSnap(&shot, path, NULL, &shot.lpHF->lpFirstFC, NULL);
    assert(!shot.fIncomplete && hashCalls == 1 && reuseCalls == 0);
    assert(!shot.lpHF->lpFirstFC->lpFirstSubFC->nChkSumUnknown);
    shot.lpUsnSnapshot = NULL;
    FreeShot(&shot);

    shot.lpHF = MYALLOC0(sizeof(HEADFILE));
    shot.lpUsnSnapshot = &snapshot;
    hashCalls = reuseCalls = 0;
    GetFilesSnapAgainst(&shot, path, NULL, &shot.lpHF->lpFirstFC, NULL, NULL, TRUE);
    assert(!shot.fIncomplete && hashCalls == 0 && reuseCalls == 0);
    assert(shot.lpHF->lpFirstFC->lpFirstSubFC->nChkSumUnknown);
    assert(shot.lpHF->lpFirstFC->lpFirstSubFC->fUsnFlags == 0);
    FinishUsnScan(&shot);
    assert(CollectUsnEntries(shot.lpHF->lpFirstFC, NULL, 0) == 0);
    shot.lpUsnSnapshot = NULL;
    FreeShot(&shot);

    shot.fMetadataOnly = TRUE;
    shot.lpHF = MYALLOC0(sizeof(HEADFILE));
    shot.lpUsnSnapshot = &snapshot;
    hashCalls = reuseCalls = idRequests = 0;
    GetFilesSnap(&shot, path, NULL, &shot.lpHF->lpFirstFC, NULL);
    assert(!shot.fIncomplete && shot.stCounts.cFiles == 1 && idRequests == 1);
    assert(shot.lpHF->lpFirstFC->lpFirstSubFC->nFileId == 123);
    assert(shot.lpHF->lpFirstFC->lpFirstSubFC->nUsnVolume == 1);
    assert(shot.lpHF->lpFirstFC->lpFirstSubFC->nChkSumUnknown);
    assert(shot.lpHF->lpFirstFC->lpFirstSubFC->fUsnFlags == 0);
    FinishUsnScan(&shot);
    assert(hashCalls == 0 && reuseCalls == 0);
    assert(CollectUsnEntries(shot.lpHF->lpFirstFC, NULL, 0) == 0);
    shot.lpUsnSnapshot = NULL;
    shot.fFilled = TRUE;
    shot.stCounts.cAll = shot.stCounts.cDirs + shot.stCounts.cFiles;
    assert(GetTempFileName(temp, TEXT("rs"), 0, hivePath));
    SaveShot(&shot);
    assert(!fHiveWriteFailed);
    FreeShot(&shot);
    assert(LoadShot(&shot));
    assert(shot.lpHF->lpFirstFC->lpFirstSubFC->nChkSumUnknown);
    before = after = *shot.lpHF->lpFirstFC->lpFirstSubFC;
    before.nChkSum = 1;
    after.nChkSum = 2;
    CompareFiles(&before, &after);
    assert(CompareResult.stcChanged.cFiles == 0);
    FreeCompareResult();
    after.fFileMatch = NOMATCH;
    ++after.nFileSizeLow;
    CompareFiles(&before, &after);
    assert(CompareResult.stcModified.cFiles == 1);
    FreeCompareResult();
    after.fFileMatch = NOMATCH;
    after.nFileSizeLow = before.nFileSizeLow;
    ++after.nWriteDateTimeLow;
    CompareFiles(&before, &after);
    assert(CompareResult.stcModified.cFiles == 1);
    FreeCompareResult();
    FreeShot(&shot);
    assert(DeleteFile(hivePath));

    enumerationMode = 0;
    offerCachedHash = FALSE;
    shot.fMetadataOnly = TRUE;
    shot.lpHF = MYALLOC0(sizeof(HEADFILE));
    shot.lpUsnSnapshot = &snapshot;
    GetFilesSnap(&shot, path, NULL, &shot.lpHF->lpFirstFC, NULL);
    assert(!shot.fIncomplete && shot.stCounts.cFiles == 1);
    assert(shot.lpHF->lpFirstFC->lpFirstSubFC->nChkSumUnknown);
    assert(hashCalls == 0 && reuseCalls == 0);
    shot.lpUsnSnapshot = NULL;
    FreeShot(&shot);
    shot.fMetadataOnly = TRUE;
    shot.lpHF = MYALLOC0(sizeof(HEADFILE));
    GetFilesSnap(&shot, filePath, NULL, &shot.lpHF->lpFirstFC, NULL);
    assert(!shot.fIncomplete && shot.lpHF->lpFirstFC->nChkSumUnknown && hashCalls == 0);
    FreeShot(&shot);
    shot.lpHF = MYALLOC0(sizeof(HEADFILE));
    GetFilesSnap(&shot, filePath, NULL, &shot.lpHF->lpFirstFC, NULL);
    assert(!shot.fIncomplete && !shot.lpHF->lpFirstFC->nChkSumUnknown && hashCalls == 1);
    FreeShot(&shot);
    assert(DeleteFile(filePath) && RemoveDirectory(path));
}

BOOL CALLBACK DialogProc(HWND dialog, UINT message, WPARAM wParam, LPARAM lParam);

static void TestIndependentUsnOption(void)
{
    const int ids[] = { IDC_CHECKDIR, IDC_CHECKUSN, IDC_CHECKHASH, IDC_CHECKTEXT, IDC_EDITDIR, IDC_BROWSE1 };
    HWND parent, previousWindow = hWnd;
    TCHAR temp[MAX_PATH], path[MAX_PATH];
    REGSHOT shot = { 0 };
    size_t i;

    parent = CreateWindow(TEXT("STATIC"), TEXT("Regshot options test"), 0,
        0, 0, 1, 1, NULL, NULL, NULL, NULL);
    assert(parent != NULL);
    for (i = 0; i < _countof(ids); ++i) {
        assert(CreateWindow(i == 4 ? TEXT("EDIT") : TEXT("BUTTON"), TEXT(""),
            WS_CHILD | (i < 4 ? BS_AUTOCHECKBOX : 0), 0, 0, 1, 1,
            parent, (HMENU)(INT_PTR)ids[i], NULL, NULL) != NULL);
    }
    DialogProc(parent, WM_COMMAND, IDC_CHECKDIR, 0);
    assert(IsWindowEnabled(GetDlgItem(parent, IDC_CHECKUSN)));
    assert(!IsWindowEnabled(GetDlgItem(parent, IDC_EDITDIR)));
    SendDlgItemMessage(parent, IDC_CHECKUSN, BM_SETCHECK, BST_CHECKED, 0);
    DialogProc(parent, WM_COMMAND, IDC_CHECKUSN, 0);
    assert(IsWindowEnabled(GetDlgItem(parent, IDC_EDITDIR)));
    assert(IsWindowEnabled(GetDlgItem(parent, IDC_CHECKHASH)));
    assert(!IsWindowEnabled(GetDlgItem(parent, IDC_CHECKTEXT)));
    SendDlgItemMessage(parent, IDC_CHECKHASH, BM_SETCHECK, BST_CHECKED, 0);
    DialogProc(parent, WM_COMMAND, IDC_CHECKHASH, 0);
    assert(IsWindowEnabled(GetDlgItem(parent, IDC_CHECKTEXT)));
    SendDlgItemMessage(parent, IDC_CHECKHASH, BM_SETCHECK, BST_UNCHECKED, 0);
    DialogProc(parent, WM_COMMAND, IDC_CHECKHASH, 0);
    assert(!IsWindowEnabled(GetDlgItem(parent, IDC_CHECKTEXT)));
    assert(SendDlgItemMessage(parent, IDC_CHECKDIR, BM_GETCHECK, 0, 0) == BST_UNCHECKED);
    assert(GetTempPath(MAX_PATH, temp) && GetTempFileName(temp, TEXT("rs"), 0, path));
    assert(DeleteFile(path) && CreateDirectory(path, NULL));
    SetDlgItemText(parent, IDC_EDITDIR, path);
    hWnd = parent;
    hashCalls = 0;
    FileShot(&shot);
    assert(shot.fMetadataOnly && !shot.fIncomplete && shot.stCounts.cDirs == 1 && hashCalls == 0);
    FreeShot(&shot);
    SendDlgItemMessage(parent, IDC_CHECKUSN, BM_SETCHECK, BST_UNCHECKED, 0);
    DialogProc(parent, WM_COMMAND, IDC_CHECKUSN, 0);
    assert(!IsWindowEnabled(GetDlgItem(parent, IDC_EDITDIR)));
    hWnd = previousWindow;
    assert(DestroyWindow(parent) && RemoveDirectory(path));
}

static void TestTextOnlyCapture(void)
{
    const TCHAR* suffixes[] = { TEXT("\\binary.exe"), TEXT("\\settings.INI"),
        TEXT("\\unknown.dat"), TEXT("\\plain") };
    TCHAR temp[MAX_PATH], path[MAX_PATH], names[4][MAX_PATH];
    REGSHOT shot = { 0 };
    LPFILECONTENT entry;
    DWORD written;
    HANDLE file;
    size_t i;
    const BYTE binary[] = { 'M', 'Z', 0, 1, 2 };
    const BYTE text[] = { 'h', 'e', 'l', 'l', 'o', '\n' };

    assert(GetTempPath(MAX_PATH, temp) && GetTempFileName(temp, TEXT("rs"), 0, path));
    assert(DeleteFile(path) && CreateDirectory(path, NULL));
    for (i = 0; i < _countof(names); ++i) {
        _tcscpy_s(names[i], MAX_PATH, path);
        _tcscat_s(names[i], MAX_PATH, suffixes[i]);
        file = CreateFile(names[i], GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        assert(file != INVALID_HANDLE_VALUE);
        assert(WriteFile(file, i < 2 ? binary : text,
            i < 2 ? sizeof(binary) : sizeof(text), &written, NULL));
        assert(CloseHandle(file));
    }
    shot.fTextOnly = TRUE;
    shot.lpHF = MYALLOC0(sizeof(HEADFILE));
    GetFilesSnap(&shot, path, NULL, &shot.lpHF->lpFirstFC, NULL);
    assert(!shot.fIncomplete && shot.stCounts.cFiles == 4);
    for (i = 0; i < _countof(names); ++i) {
        entry = FindSnapshotEntry(shot.lpHF->lpFirstFC->lpFirstSubFC, NULL, 0,
            _tcsrchr(names[i], (TCHAR)'\\') + 1, FILE_ATTRIBUTE_NORMAL);
        assert(entry != NULL && entry->nChkSumUnknown == (i == 0));
    }
    shot.fFilled = TRUE;
    shot.stCounts.cAll = shot.stCounts.cDirs + shot.stCounts.cFiles;
    assert(GetTempFileName(temp, TEXT("rs"), 0, hivePath));
    SaveShot(&shot);
    assert(!fHiveWriteFailed);
    FreeShot(&shot);
    assert(LoadShot(&shot));
    entry = FindSnapshotEntry(shot.lpHF->lpFirstFC->lpFirstSubFC, NULL, 0,
        TEXT("binary.exe"), FILE_ATTRIBUTE_NORMAL);
    assert(entry != NULL && entry->nChkSumUnknown);
    FreeShot(&shot);
    assert(DeleteFile(hivePath));

    shot.lpHF = MYALLOC0(sizeof(HEADFILE));
    GetFilesSnap(&shot, path, NULL, &shot.lpHF->lpFirstFC, NULL);
    for (entry = shot.lpHF->lpFirstFC->lpFirstSubFC; entry != NULL; entry = entry->lpBrotherFC)
        assert(!entry->nChkSumUnknown);
    FreeShot(&shot);
    for (i = 0; i < _countof(names); ++i)
        assert(DeleteFile(names[i]));
    assert(RemoveDirectory(path));
}

static void TestEnumerationRecovery(void)
{
    TCHAR temp[MAX_PATH], path[MAX_PATH], first[MAX_PATH], second[MAX_PATH];
    REGSHOT shot = { 0 };
    USN_SNAPSHOT snapshot = { 0 };
    LPFILECONTENT root = NULL;
    HANDLE file;

    assert(GetTempPath(MAX_PATH, temp) != 0);
    assert(GetTempFileName(temp, TEXT("rs"), 0, path));
    assert(DeleteFile(path) && CreateDirectory(path, NULL));
    _tcscpy_s(first, MAX_PATH, path);
    _tcscat_s(first, MAX_PATH, TEXT("\\first"));
    _tcscpy_s(second, MAX_PATH, path);
    _tcscat_s(second, MAX_PATH, TEXT("\\second"));
    file = CreateFile(first, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    assert(file != INVALID_HANDLE_VALUE && CloseHandle(file));
    file = CreateFile(second, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    assert(file != INVALID_HANDLE_VALUE && CloseHandle(file));
    shot.lpUsnSnapshot = &snapshot;
    enumerationMode = 1;
    GetFilesSnap(&shot, path, NULL, &root, NULL);
    assert(classicRestarts == 1);
    assert(!shot.fIncomplete && shot.stCounts.cFiles == 2 && shot.stCounts.cDirs == 1);
    assert(root->lpFirstSubFC && root->lpFirstSubFC->lpBrotherFC
        && !root->lpFirstSubFC->lpBrotherFC->lpBrotherFC);
    FreeAllFileContents(root);
    ZeroMemory(&shot, sizeof(shot));
    root = NULL;
    enumerationMode = 2;
    GetFilesSnap(&shot, path, NULL, &root, NULL);
    assert(shot.fIncomplete);
    FreeAllFileContents(root);
    ZeroMemory(&shot, sizeof(shot));
    root = NULL;
    enumerationMode = 6;
    GetFilesSnap(&shot, path, NULL, &root, NULL);
    assert(!shot.fIncomplete && shot.cSkippedDirs == 1);
    assert(root->nScanError == ERROR_ACCESS_DENIED && root->lpFirstSubFC == NULL);
    assert(shot.stCounts.cFiles == 0 && shot.stCounts.cDirs == 1);
    FreeAllFileContents(root);
    ZeroMemory(&shot, sizeof(shot));
    root = NULL;
    enumerationMode = 3;
    GetFilesSnap(&shot, path, NULL, &root, NULL);
    assert(!shot.fIncomplete && shot.cSkippedDirs == 1);
    assert(root->nScanError == ERROR_ACCESS_DENIED && root->lpFirstSubFC == NULL);
    FreeAllFileContents(root);
    ZeroMemory(&shot, sizeof(shot));
    root = NULL;
    enumerationMode = 4;
    directoryOpens = 0;
    GetFilesSnap(&shot, path, NULL, &root, NULL);
    assert(!shot.fIncomplete && shot.cSkippedDirs == 1 && directoryOpens == 1);
    assert(root->lpFirstSubFC->nScanError == ERROR_CANT_ACCESS_FILE);
    assert(root->lpFirstSubFC->lpFirstSubFC == NULL);
    FreeAllFileContents(root);
    ZeroMemory(&shot, sizeof(shot));
    root = NULL;
    enumerationMode = 5;
    GetFilesSnap(&shot, path, NULL, &root, NULL);
    assert(shot.fIncomplete && shot.cSkippedDirs == 0);
    FreeAllFileContents(root);
    enumerationMode = 0;
    assert(DeleteFile(first) && DeleteFile(second) && RemoveDirectory(path));
}

static void TestEntryPathReuse(void)
{
    TCHAR temp[MAX_PATH], path[MAX_PATH], child[MAX_PATH], names[4][MAX_PATH];
    const TCHAR* suffixes[] = {
        TEXT("\\a"), TEXT("\\a-much-longer-file-name"), TEXT("\\skip"),
        TEXT("\\child\\file-\x03A9")
    };
    LPTSTR skips[] = { TEXT("skip"), names[3], NULL };
    LPTSTR* previousSkips = lprgszFileSkipStrings;
    REGSHOT shot = { 0 };
    LPFILECONTENT root = NULL, entry;
    QWORD expected = 0;
    size_t i;
    DWORD written;
    HANDLE file;

    assert(GetTempPath(MAX_PATH, temp) && GetTempFileName(temp, TEXT("rs"), 0, path));
    assert(DeleteFile(path) && CreateDirectory(path, NULL));
    _tcscpy_s(child, MAX_PATH, path);
    _tcscat_s(child, MAX_PATH, TEXT("\\child"));
    assert(CreateDirectory(child, NULL));
    for (i = 0; i < _countof(names); ++i) {
        _tcscpy_s(names[i], MAX_PATH, path);
        _tcscat_s(names[i], MAX_PATH, suffixes[i]);
        file = CreateFile(names[i], GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        assert(file != INVALID_HANDLE_VALUE);
        assert(WriteFile(file, &i, sizeof(i), &written, NULL) && written == sizeof(i));
        assert(CloseHandle(file));
    }
    failAllocationAfter = 3;
    GetFilesSnap(&shot, path, NULL, &root, NULL);
    failAllocationAfter = -1;
    assert(shot.fIncomplete && root != NULL && root->lpFirstSubFC == NULL);
    FreeAllFileContents(root);
    ZeroMemory(&shot, sizeof(shot));
    root = NULL;
    fileAllocations = 0;
    countFileAllocations = TRUE;
    GetFilesSnap(&shot, path, NULL, &root, NULL);
    countFileAllocations = FALSE;
    assert(!shot.fIncomplete && shot.stCounts.cFiles == 4 && shot.stCounts.cDirs == 2);
    // Two allocations per entry, plus one reusable path per directory and root setup.
    assert(fileAllocations <= 15);
    for (entry = root->lpFirstSubFC; entry != NULL; entry = entry->lpBrotherFC) {
        LPFILECONTENT content = ISDIR(entry->nFileAttributes) ? entry->lpFirstSubFC : entry;
        LPTSTR fullName = GetWholeFileName(content, 0);

        assert(fullName != NULL && ChecksumFromFile(fullName, &expected));
        assert(!content->nChkSumUnknown && content->nChkSum == expected);
        MYFREE(fullName);
    }
    FreeAllFileContents(root);
    ZeroMemory(&shot, sizeof(shot));
    root = NULL;
    lprgszFileSkipStrings = skips;
    fileAllocations = 0;
    countFileAllocations = TRUE;
    GetFilesSnap(&shot, path, NULL, &root, NULL);
    countFileAllocations = FALSE;
    assert(!shot.fIncomplete && shot.stCounts.cFiles == 2 && shot.stCounts.cDirs == 2);
    assert(fileAllocations <= 11);
    for (entry = root->lpFirstSubFC; entry != NULL; entry = entry->lpBrotherFC) {
        assert(_tcscmp(entry->lpszFileName, TEXT("skip")) != 0);
        if (ISDIR(entry->nFileAttributes))
            assert(entry->lpFirstSubFC == NULL);
    }
    lprgszFileSkipStrings = previousSkips;
    FreeAllFileContents(root);
    for (i = 0; i < _countof(names); ++i)
        assert(DeleteFile(names[i]));
    assert(RemoveDirectory(child) && RemoveDirectory(path));
}

static void CaptureTestFiles(LPREGSHOT shot, LPTSTR path)
{
    shot->lpHF = MYALLOC0(sizeof(HEADFILE));
    GetFilesSnap(shot, path, NULL, &shot->lpHF->lpFirstFC, NULL);
    assert(!shot->fIncomplete);
    shot->stCounts.cAll = shot->stCounts.cFiles + shot->stCounts.cDirs;
    shot->fFilled = TRUE;
}

static void WriteTestFile(LPCTSTR path, const char* text, const FILECONTENT* before)
{
    DWORD written, size = (DWORD)strlen(text);
    HANDLE file = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    assert(file != INVALID_HANDLE_VALUE);
    assert(WriteFile(file, text, size, &written, NULL) && written == size);
    if (before != NULL) {
        FILETIME time;

        time.dwLowDateTime = before->nWriteDateTimeLow;
        time.dwHighDateTime = before->nWriteDateTimeHigh;
        assert(SetFileTime(file, NULL, NULL, &time));
    }
    assert(CloseHandle(file));
}

static void TestSecondSnapshotHashing(void)
{
    const TCHAR* suffixes[] = {
        TEXT("\\stable"), TEXT("\\same-size"), TEXT("\\size"),
        TEXT("\\date"), TEXT("\\attributes"), TEXT("\\unknown"),
        TEXT("\\child\\file-\x03A9"), TEXT("\\deleted"), TEXT("\\added")
    };
    TCHAR temp[MAX_PATH], path[MAX_PATH], child[MAX_PATH], names[9][MAX_PATH];
    LPFILECONTENT root, before, after;
    REGSHOT full = { 0 };
    NAMEINDEXENTRY* index;
    size_t i, count;
    QWORD stableHash;

    assert(!Shot1.fFilled && !Shot2.fFilled);
    assert(GetTempPath(MAX_PATH, temp) && GetTempFileName(temp, TEXT("rs"), 0, path));
    assert(DeleteFile(path) && CreateDirectory(path, NULL));
    _tcscpy_s(child, MAX_PATH, path);
    _tcscat_s(child, MAX_PATH, TEXT("\\child"));
    assert(CreateDirectory(child, NULL));
    for (i = 0; i < _countof(names); ++i) {
        _tcscpy_s(names[i], MAX_PATH, path);
        _tcscat_s(names[i], MAX_PATH, suffixes[i]);
        if (i != 8)
            WriteTestFile(names[i], "before", NULL);
    }
    hashCalls = 0;
    CaptureTestFiles(&Shot1, path);
    assert(hashCalls == 8);
    root = Shot1.lpHF->lpFirstFC;
    before = FindSnapshotEntry(root->lpFirstSubFC, NULL, 0, TEXT("unknown"), FILE_ATTRIBUTE_NORMAL);
    assert(before != NULL);
    before->nChkSumUnknown = TRUE;
    assert(GetTempFileName(temp, TEXT("rs"), 0, hivePath));
    SaveShot(&Shot1);
    assert(!fHiveWriteFailed);
    FreeShot(&Shot1);
    assert(LoadShot(&Shot1) && Shot1.fLoaded);
    root = Shot1.lpHF->lpFirstFC;
    before = FindSnapshotEntry(root->lpFirstSubFC, NULL, 0, TEXT("stable"), FILE_ATTRIBUTE_NORMAL);
    assert(before != NULL && !before->nChkSumUnknown);
    stableHash = before->nChkSum;
    _tcsupr_s(before->lpszFileName, before->cchFileName + 1);
    for (before = root->lpFirstSubFC; before != NULL; before = before->lpBrotherFC)
        before->fFileMatch = ISMATCH;
    failAllocationAfter = 0;
    index = IndexFiles(root->lpFirstSubFC, &count, FALSE);
    failAllocationAfter = -1;
    assert(index == NULL && count > 1);
    assert(FindSnapshotEntry(root->lpFirstSubFC, index, count, TEXT("stable"),
        FILE_ATTRIBUTE_NORMAL) != NULL);

    before = FindSnapshotEntry(root->lpFirstSubFC, NULL, 0, TEXT("same-size"), FILE_ATTRIBUTE_NORMAL);
    WriteTestFile(names[1], "AFTER!", before);
    WriteTestFile(names[2], "a larger file", NULL);
    before = FindSnapshotEntry(root->lpFirstSubFC, NULL, 0, TEXT("date"), FILE_ATTRIBUTE_NORMAL);
    {
        FILECONTENT changed = *before;

        changed.nWriteDateTimeHigh++;
        WriteTestFile(names[3], "before", &changed);
    }
    before = FindSnapshotEntry(root->lpFirstSubFC, NULL, 0, TEXT("attributes"), FILE_ATTRIBUTE_NORMAL);
    assert(SetFileAttributes(names[4], before->nFileAttributes ^ FILE_ATTRIBUTE_HIDDEN));
    before = FindSnapshotEntry(root->lpFirstSubFC, NULL, 0, TEXT("child"), FILE_ATTRIBUTE_DIRECTORY);
    WriteTestFile(names[6], "AFTER!", before->lpFirstSubFC);
    assert(DeleteFile(names[7]));
    WriteTestFile(names[8], "new", NULL);

    hashCalls = 0;
    CaptureTestFiles(&Shot2, path);
    assert(hashCalls == 3 && Shot2.stCounts.cFiles == 8);
    for (i = 0; i < _countof(names); ++i) {
        const TCHAR* name = _tcsrchr(names[i], (TCHAR)'\\') + 1;
        LPFILECONTENT siblings = Shot2.lpHF->lpFirstFC->lpFirstSubFC;

        if (i == 6) {
            after = FindSnapshotEntry(siblings, NULL, 0, TEXT("child"), FILE_ATTRIBUTE_DIRECTORY);
            siblings = after->lpFirstSubFC;
        }
        after = FindSnapshotEntry(siblings, NULL, 0, name, FILE_ATTRIBUTE_NORMAL);
        if (i == 7) {
            assert(after == NULL);
            continue;
        }
        assert(after != NULL);
        assert(after->nChkSumUnknown == (i != 0 && i != 1 && i != 6));
        if (i == 0)
            assert(after->nChkSum == stableHash);
        if (i == 1) {
            before = FindSnapshotEntry(root->lpFirstSubFC, NULL, 0, name, FILE_ATTRIBUTE_NORMAL);
            assert(after->nChkSum != before->nChkSum);
        }
    }
    ClearHeadFileMatchFlags(Shot1.lpHF);
    CompareHeadFiles(Shot1.lpHF, Shot2.lpHF);
    assert(CompareResult.stcModified.cFiles == 5 && CompareResult.stcAdded.cFiles == 1
        && CompareResult.stcDeleted.cFiles == 1);
    FreeCompareResult();
    hashCalls = 0;
    CaptureTestFiles(&full, path);
    assert(hashCalls == 8);
    ClearHeadFileMatchFlags(Shot1.lpHF);
    CompareHeadFiles(Shot1.lpHF, full.lpHF);
    assert(CompareResult.stcModified.cFiles == 5 && CompareResult.stcAdded.cFiles == 1
        && CompareResult.stcDeleted.cFiles == 1);
    FreeCompareResult();
    FreeShot(&full);
    SaveShot(&Shot2);
    assert(!fHiveWriteFailed);
    FreeShot(&Shot2);
    assert(LoadShot(&Shot2));
    after = FindSnapshotEntry(Shot2.lpHF->lpFirstFC->lpFirstSubFC, NULL, 0,
        TEXT("size"), FILE_ATTRIBUTE_NORMAL);
    assert(after != NULL && after->nChkSumUnknown);
    FreeShot(&Shot2);
    Shot1.fFilled = FALSE;
    hashCalls = 0;
    CaptureTestFiles(&Shot2, path);
    assert(hashCalls == 8);
    FreeShot(&Shot2);
    FreeShot(&Shot1);

    CaptureTestFiles(&Shot1, names[0]);
    hashCalls = 0;
    CaptureTestFiles(&Shot2, names[0]);
    assert(hashCalls == 1 && !Shot2.lpHF->lpFirstFC->nChkSumUnknown);
    FreeShot(&Shot2);
    Shot1.lpHF->lpFirstFC->nFileSizeHigh++;
    hashCalls = 0;
    CaptureTestFiles(&Shot2, names[0]);
    assert(hashCalls == 0 && Shot2.lpHF->lpFirstFC->nChkSumUnknown);
    FreeShot(&Shot2);
    hashCalls = 0;
    CaptureTestFiles(&Shot2, names[8]);
    assert(hashCalls == 0 && Shot2.lpHF->lpFirstFC->nChkSumUnknown);
    FreeShot(&Shot2);
    FreeShot(&Shot1);
    assert(DeleteFile(hivePath));
    for (i = 0; i < _countof(names); ++i) {
        if (i != 7) {
            assert(SetFileAttributes(names[i], FILE_ATTRIBUTE_NORMAL));
            assert(DeleteFile(names[i]));
        }
    }
    assert(RemoveDirectory(child) && RemoveDirectory(path));
}

static void TestSkippedComparison(void)
{
    FILECONTENT before = { 0 }, after = { 0 }, child = { 0 };

    before.lpszFileName = after.lpszFileName = TEXT("root");
    before.nFileAttributes = after.nFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
    child.lpszFileName = TEXT("file");
    child.nFileAttributes = FILE_ATTRIBUTE_NORMAL;
    before.lpFirstSubFC = &child;
    after.nScanError = ERROR_ACCESS_DENIED;
    CompareFiles(&before, &after);
    assert(CompareResult.stcChanged.cFiles == 0 && CompareResult.stcChanged.cDirs == 0);
    FreeCompareResult();
    ClearFileMatchFlags(&before);
    ClearFileMatchFlags(&after);
    CompareFiles(&after, &before);
    assert(CompareResult.stcChanged.cFiles == 0 && CompareResult.stcChanged.cDirs == 0);
    FreeCompareResult();
    ClearFileMatchFlags(&before);
    ClearFileMatchFlags(&after);
    after.nScanError = 0;
    CompareFiles(&before, &after);
    assert(CompareResult.stcDeleted.cFiles == 1);
    FreeCompareResult();
}

static void TestSkippedSaveLoad(void)
{
    TCHAR temp[MAX_PATH], path[MAX_PATH];
    REGSHOT shot = { 0 };

    assert(GetTempPath(MAX_PATH, temp) != 0);
    assert(GetTempFileName(temp, TEXT("rs"), 0, path));
    assert(DeleteFile(path) && CreateDirectory(path, NULL));
    assert(GetTempFileName(temp, TEXT("rs"), 0, hivePath));
    shot.lpHF = MYALLOC0(sizeof(HEADFILE));
    assert(shot.lpHF != NULL);
    enumerationMode = 3;
    GetFilesSnap(&shot, path, NULL, &shot.lpHF->lpFirstFC, NULL);
    enumerationMode = 0;
    shot.fFilled = TRUE;
    shot.stCounts.cAll = shot.stCounts.cDirs;
    SaveShot(&shot);
    assert(!fHiveWriteFailed);
    FreeShot(&shot);
    assert(LoadShot(&shot));
    assert(shot.fFilled && shot.fLoaded && shot.cSkippedDirs == 1);
    assert(shot.lpHF->lpFirstFC->nScanError == ERROR_ACCESS_DENIED);
    assert(shot.lpHF->lpFirstFC->lpFirstSubFC == NULL);
    {
        int previousErrors = loadErrors;

        failHiveWrite = TRUE;
        SaveShot(&shot);
        failHiveWrite = FALSE;
        assert(fHiveWriteFailed && loadErrors == previousErrors + 1);
        assert(shot.fFilled);
    }
    FreeShot(&shot);
    assert(DeleteFile(hivePath) && RemoveDirectory(path));
}

static void TestBaselinePermissions(void)
{
    TCHAR temp[MAX_PATH], path[MAX_PATH], blocker[MAX_PATH];
    BYTE payload[] = { 1, 2, 3 }, read[3];
    DWORD bytes;
    HANDLE file;
    PSECURITY_DESCRIPTOR security;
    SECURITY_ATTRIBUTES attributes;

    assert(GetTempPath(MAX_PATH, temp) != 0);
    assert(GetTempFileName(temp, TEXT("rs"), 0, path));
    file = CreateFile(path, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    assert(file != INVALID_HANDLE_VALUE);
    assert(!TrustedBaselineFile(file));
    CloseHandle(file);
    assert(DeleteFile(path));
    assert(CanUseJournal());  // CI runs elevated, as required by the USN feature.
    assert(ReplaceFileAtomically(path, payload, sizeof(payload)));
    file = CreateFile(path, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    assert(file != INVALID_HANDLE_VALUE && TrustedBaselineFile(file));
    assert(ReadFile(file, read, sizeof(read), &bytes, NULL) && bytes == sizeof(read)
        && memcmp(read, payload, sizeof(read)) == 0);
    CloseHandle(file);

    _tcscpy_s(blocker, MAX_PATH, path);
    _tcscat_s(blocker, MAX_PATH, TEXT(".tmp"));
    assert(CreateHardLink(blocker, path, NULL));
    assert(!ReplaceFileAtomically(path, (const BYTE*)"bad", 3));
    file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    assert(ReadFile(file, read, sizeof(read), &bytes, NULL) && memcmp(read, payload, sizeof(read)) == 0);
    CloseHandle(file);
    assert(DeleteFile(blocker) && DeleteFile(path));

    assert(ConvertStringSecurityDescriptorToSecurityDescriptor(
        TEXT("O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;BU)"), SDDL_REVISION_1, &security, NULL));
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = security;
    attributes.bInheritHandle = FALSE;
    file = CreateFile(path, GENERIC_WRITE | READ_CONTROL, 0, &attributes, CREATE_NEW, 0, NULL);
    assert(file != INVALID_HANDLE_VALUE && !TrustedBaselineFile(file));
    CloseHandle(file);
    LocalFree(security);
    assert(DeleteFile(path));
}

static void PrintRegistryProfile(const char* label, REGISTRY_PROFILE* profile, LONGLONG frequency)
{
    printf("%-18s %10llu calls %10.3f seconds\n",
        label, profile->calls, (double)profile->ticks / (double)frequency);
}

static int BenchmarkRegistry(void)
{
    REGSHOT shot = { 0 };
    LARGE_INTEGER frequency, start, end;
    LPTSTR paths[] = { TEXT("HKLM"), TEXT("HKU") };
    HKEY roots[] = { HKEY_LOCAL_MACHINE, HKEY_USERS };
    size_t i;

    assert(QueryPerformanceFrequency(&frequency));
    printf("Registry profile: %s buffer capacity; full capture, no skip list; counts and timings only.\n",
        profileLegacyCapacity ? "legacy shared" : "per-key");
    puts("Registry contents are not printed or saved.");
    profileRegistry = TRUE;
    QueryPerformanceCounter(&start);
    for (i = 0; i < _countof(roots); ++i) {
        REGSHOT part = { 0 };
        LARGE_INTEGER partStart, partEnd;

        QueryPerformanceCounter(&partStart);
        GetRegistrySnap(&part, roots[i], i == 0 ? lpszHKLMShort : lpszHKUShort,
            NULL, i == 0 ? &shot.lpHKLM : &shot.lpHKU);
        QueryPerformanceCounter(&partEnd);
        _tprintf(TEXT("%s: keys=%lu values=%lu unavailable=%lu incomplete=%u time=%.3fs\n"),
            paths[i], part.stCounts.cKeys, part.stCounts.cValues, part.cSkippedRegKeys,
            part.fIncomplete, (double)(partEnd.QuadPart - partStart.QuadPart) / (double)frequency.QuadPart);
        shot.fIncomplete |= part.fIncomplete;
    }
    QueryPerformanceCounter(&end);
    profileRegistry = FALSE;
    printf("Total capture: %.3f seconds\n", (double)(end.QuadPart - start.QuadPart) / (double)frequency.QuadPart);
    PrintRegistryProfile("RegOpenKeyEx", &profileOpen, frequency.QuadPart);
    PrintRegistryProfile("RegCloseKey", &profileClose, frequency.QuadPart);
    PrintRegistryProfile("RegQueryInfoKey", &profileInfo, frequency.QuadPart);
    PrintRegistryProfile("RegEnumValue", &profileValues, frequency.QuadPart);
    PrintRegistryProfile("RegEnumKeyEx", &profileKeys, frequency.QuadPart);
    PrintRegistryProfile("HeapAlloc", &profileAlloc, frequency.QuadPart);
    printf("RegEnumValue mean offered data capacity: %.0f bytes; maximum: %lu bytes\n",
        profileValues.calls != 0 ? (double)profileDataBytes / (double)profileValues.calls : 0,
        profileMaxDataCapacity);
    {
        BOOL incomplete = shot.fIncomplete;

        FreeShot(&shot);
        MYFREE(lpStringBuffer);
        MYFREE(lpDataBuffer);
        lpStringBuffer = NULL;
        lpDataBuffer = NULL;
        return incomplete ? 1 : 0;
    }
}

int main(int argc, char** argv)
{
    TCHAR message[REGSHOT_MESSAGE_LENGTH];
    TCHAR dirs[EXTDIRLEN], openDir[MAX_PATH], saveDir[MAX_PATH];
    LPTSTR noSkips[] = { NULL };

    hHeap = GetProcessHeap();
    setvbuf(stdout, NULL, _IONBF, 0);
    lpszMessage = message;
    lpszExtDir = dirs;
    lpszLastOpenDir = openDir;
    lpszLastSaveDir = saveDir;
    lprgszRegSkipStrings = noSkips;
    lprgszFileSkipStrings = noSkips;
    SetTextsToDefaultLanguage();
    nLastTime = GetTickCount();
    if (argc == 2 && strcmp(argv[1], "--benchmark-registry-legacy-capacity") == 0) {
        profileLegacyCapacity = TRUE;
        return BenchmarkRegistry();
    }
    if (argc == 2 && strcmp(argv[1], "--benchmark-registry") == 0)
        return BenchmarkRegistry();
    puts("Testing registry formatting");
    TestRegistryFormatting();
    puts("Testing Unicode HTML report encoding");
    TestHtmlReportEncoding();
    puts("Testing value growth");
    TestValueRetry();
    puts("Testing subkey growth");
    TestKeyRetry();
    puts("Testing registry availability and save/load");
    TestRegistryAvailability();
    puts("Testing indexed comparisons");
    TestIndexedComparison();
    puts("Testing hive validation");
    TestHiveValidation();
    puts("Testing load cleanup");
    TestLoadFailures();
    puts("Testing path trimming");
    TestPathTrimming();
    puts("Testing USN metadata-only snapshots");
    TestMetadataOnly();
    puts("Testing independent USN option");
    TestIndependentUsnOption();
    puts("Testing text-only capture");
    TestTextOnlyCapture();
    puts("Testing enumeration recovery");
    TestEnumerationRecovery();
    puts("Testing directory entry path reuse");
    TestEntryPathReuse();
    puts("Testing selective second-snapshot hashing");
    TestSecondSnapshotHashing();
    puts("Testing skipped-directory comparisons");
    TestSkippedComparison();
    puts("Testing skipped-directory save/load");
    TestSkippedSaveLoad();
    puts("Testing baseline permissions");
    TestBaselinePermissions();
    puts("Snapshot logic tests passed");
    return 0;
}
