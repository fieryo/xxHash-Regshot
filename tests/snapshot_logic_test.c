#include "../HackerslangsRegShot/common.h"

static int valueCalls;
static BOOL keepGrowing;
static int failAllocationAfter = -1;
static BOOL failBulkRead;
static int readCalls;
static TCHAR hivePath[MAX_PATH];
static int loadErrors;

static LPVOID WINAPI FakeHeapAlloc(HANDLE heap, DWORD flags, SIZE_T size)
{
    if (failAllocationAfter == 0)
        return NULL;
    if (failAllocationAfter > 0)
        --failAllocationAfter;
    return HeapAlloc(heap, flags, size);
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
    assert(index == 7);
    ++valueCalls;
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

#undef RegEnumValue
#define RegEnumValue FakeRegEnumValue
#undef GetOpenFileName
#define GetOpenFileName FakeOpenFileName
#define HeapAlloc FakeHeapAlloc
#define ReadFile FakeReadFile
#define ErrMsg FakeErrMsg
#include "../HackerslangsRegShot/regshot.c"
#include "../HackerslangsRegShot/usnsnapshot.c"
#include "../HackerslangsRegShot/fileenum.h"

static int enumerationMode;
static int classicRestarts;
static BOOL FakeSnapshotDirOpen(SNAPSHOT_DIR* dir, LPCTSTR pattern, BOOL wantIds,
    const SNAPSHOT_DIR* parent, ULONGLONG directoryId, WIN32_FIND_DATA* data, ULONGLONG* id)
{
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
    if ((enumerationMode == 1 && dir->ids) || enumerationMode == 2) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return SnapshotDirNext(dir, data, id);
}

static DWORD FakeSnapshotVolume(USN_SNAPSHOT* snapshot, const WCHAR* guid, DWORD serial)
{
    return enumerationMode == 1 ? 1 : UsnSnapshotVolume(snapshot, guid, serial);
}

#define SnapshotDirOpen FakeSnapshotDirOpen
#define SnapshotDirNext FakeSnapshotDirNext
#define UsnSnapshotVolume FakeSnapshotVolume
#include "../HackerslangsRegShot/fileshot.c"
#undef SnapshotDirOpen
#undef SnapshotDirNext
#undef UsnSnapshotVolume

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

static void TestValueRetry(void)
{
    DWORD nameLength, type, dataLength;

    nStringBufferSize = sizeof(TCHAR);
    lpStringBuffer = MYALLOC(nStringBufferSize);
    nDataBufferSize = 1;
    lpDataBuffer = MYALLOC(nDataBufferSize);
    assert(EnumerateSnapshotValue(NULL, 7, &nameLength, &type, &dataLength) == ERROR_SUCCESS);
    assert(valueCalls == 2 && nameLength == 1 && dataLength == 1 && lpDataBuffer[0] == 0x42);
    valueCalls = 0;
    keepGrowing = TRUE;
    assert(EnumerateSnapshotValue(NULL, 7, &nameLength, &type, &dataLength) == ERROR_MORE_DATA);
    assert(valueCalls == 9);
    MYFREE(lpStringBuffer);
    MYFREE(lpDataBuffer);
    lpStringBuffer = NULL;
    lpDataBuffer = NULL;
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
    file.ofsFileName = 384;
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
    enumerationMode = 0;
    assert(DeleteFile(first) && DeleteFile(second) && RemoveDirectory(path));
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

int main(void)
{
    TCHAR message[REGSHOT_MESSAGE_LENGTH];
    TCHAR dirs[EXTDIRLEN], openDir[MAX_PATH];
    LPTSTR noSkips[] = { NULL };

    hHeap = GetProcessHeap();
    setvbuf(stdout, NULL, _IONBF, 0);
    lpszMessage = message;
    lpszExtDir = dirs;
    lpszLastOpenDir = openDir;
    lprgszRegSkipStrings = noSkips;
    lprgszFileSkipStrings = noSkips;
    SetTextsToDefaultLanguage();
    nLastTime = GetTickCount();
    puts("Testing registry formatting");
    TestRegistryFormatting();
    puts("Testing value growth");
    TestValueRetry();
    puts("Testing hive validation");
    TestHiveValidation();
    puts("Testing load cleanup");
    TestLoadFailures();
    puts("Testing path trimming");
    TestPathTrimming();
    puts("Testing enumeration recovery");
    TestEnumerationRecovery();
    puts("Testing baseline permissions");
    TestBaselinePermissions();
    puts("Snapshot logic tests passed");
    return 0;
}
