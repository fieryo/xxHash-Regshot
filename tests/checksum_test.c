#include "../xxHash-Regshot/checksum.h"
#include "../xxHash-Regshot/third_party/xxhash/xxhash.h"
#include <assert.h>
#include <stdio.h>

static int readCalls, allocationCalls, failReadCall;
static BOOL failAllocation;
static DWORD firstReadSize;

static QWORD ExpectedChecksum(const unsigned char* data, DWORD size)
{
    return (QWORD)XXH3_64bits(data, size);
}

static BOOL WINAPI CountReadFile(HANDLE file, LPVOID buffer, DWORD size,
    LPDWORD bytesRead, LPOVERLAPPED overlapped)
{
    if (readCalls == 0)
        firstReadSize = size;
    if (++readCalls == failReadCall) {
        SetLastError(ERROR_READ_FAULT);
        return FALSE;
    }
    return ReadFile(file, buffer, size, bytesRead, overlapped);
}

static LPVOID WINAPI CountHeapAlloc(HANDLE heap, DWORD flags, SIZE_T size)
{
    ++allocationCalls;
    return failAllocation ? NULL : HeapAlloc(heap, flags, size);
}

#define ReadFile CountReadFile
#define HeapAlloc CountHeapAlloc
#include "../xxHash-Regshot/checksum.c"
#undef ReadFile
#undef HeapAlloc

static int TestTextFile(LPCTSTR path, const unsigned char* data, DWORD size,
    CHECKSUM_RESULT expected, DWORD expectedFirstRead)
{
    DWORD written;
    QWORD hash = 123;
    HANDLE file = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    CHECKSUM_RESULT result;

    if (file == INVALID_HANDLE_VALUE)
        return 0;
    if (!WriteFile(file, data, size, &written, NULL) || written != size) {
        CloseHandle(file);
        return 0;
    }
    CloseHandle(file);
    readCalls = allocationCalls = 0;
    result = ChecksumTextFile(path, &hash);
    return result == expected && firstReadSize == expectedFirstRead
        && (expected == CHECKSUM_OK ? hash == ExpectedChecksum(data, size) : hash == 123)
        && (expected != CHECKSUM_NOT_TEXT || (readCalls == 1 && allocationCalls == 0));
}

static int TestTextDetection(LPCTSTR directory)
{
    TCHAR path[MAX_PATH], workdir[MAX_PATH];
    static unsigned char large[256 * 1024 + 19];
    const unsigned char binary[] = { 'M', 'Z', 0, 1, 2, 3 };
    const unsigned char utf16le[] = { 0xff, 0xfe, 'a', 0, '\n', 0 };
    const unsigned char utf16be[] = { 0xfe, 0xff, 0, 'a' };
    const unsigned char utf32le[] = { 0xff, 0xfe, 0, 0, 'a', 0, 0, 0 };
    const unsigned char utf32be[] = { 0, 0, 0xfe, 0xff, 0, 0, 0, 'a' };
    const unsigned char utf16NoBom[] = { 'a', 0, 'b', 0, '\n', 0 };
    const unsigned char utf8[] = { 0xef, 0xbb, 0xbf, 't', 'e', 'x', 't', '\n' };
    const unsigned char control[] = { 't', 'e', 'x', 't', 1 };
    size_t i;
    int ok;

    assert(IsKnownTextExtension(TEXT("C:\\dir.with.dot\\SETTINGS.INI")));
    assert(IsKnownTextExtension(TEXT("C:\\dir\\.gitignore")));
    assert(!IsKnownTextExtension(TEXT("C:\\dir.ini\\extensionless")));
    assert(!IsKnownTextExtension(TEXT("binary.exe")));
    assert(!IsKnownTextExtension(TEXT("image.svgz")));
    if (!GetTempFileName(directory, TEXT("txt"), 0, workdir)
        || !DeleteFile(workdir) || !CreateDirectory(workdir, NULL))
        return 0;
    _tcscpy_s(path, MAX_PATH, workdir);
    _tcscat_s(path, MAX_PATH, TEXT("\\test.ini"));
    ok = TestTextFile(path, binary, sizeof(binary), CHECKSUM_OK, SMALL_FILE_BUFFER_SIZE + 1);
    if (!DeleteFile(path))
        return 0;
    _tcscpy_s(path, MAX_PATH, workdir);
    _tcscat_s(path, MAX_PATH, TEXT("\\test.unknown"));
    memset(large, 'x', sizeof(large));
    ok = ok && TestTextFile(path, large, sizeof(large), CHECKSUM_OK, TEXT_SAMPLE_SIZE)
        && TestTextFile(path, large, TEXT_SAMPLE_SIZE, CHECKSUM_OK, TEXT_SAMPLE_SIZE)
        && TestTextFile(path, large, SMALL_FILE_BUFFER_SIZE, CHECKSUM_OK, TEXT_SAMPLE_SIZE)
        && TestTextFile(path, large, SMALL_FILE_BUFFER_SIZE + 1, CHECKSUM_OK, TEXT_SAMPLE_SIZE)
        && TestTextFile(path, binary, sizeof(binary), CHECKSUM_NOT_TEXT, TEXT_SAMPLE_SIZE)
        && TestTextFile(path, control, sizeof(control), CHECKSUM_NOT_TEXT, TEXT_SAMPLE_SIZE)
        && TestTextFile(path, utf16le, sizeof(utf16le), CHECKSUM_OK, TEXT_SAMPLE_SIZE)
        && TestTextFile(path, utf16be, sizeof(utf16be), CHECKSUM_OK, TEXT_SAMPLE_SIZE)
        && TestTextFile(path, utf32le, sizeof(utf32le), CHECKSUM_OK, TEXT_SAMPLE_SIZE)
        && TestTextFile(path, utf32be, sizeof(utf32be), CHECKSUM_OK, TEXT_SAMPLE_SIZE)
        && TestTextFile(path, utf16NoBom, sizeof(utf16NoBom), CHECKSUM_OK, TEXT_SAMPLE_SIZE)
        && TestTextFile(path, utf8, sizeof(utf8), CHECKSUM_OK, TEXT_SAMPLE_SIZE)
        && TestTextFile(path, large, 0, CHECKSUM_OK, TEXT_SAMPLE_SIZE);
    large[3] = 0;
    large[4] = 1;
    ok = ok && TestTextFile(path, large, sizeof(large), CHECKSUM_NOT_TEXT, TEXT_SAMPLE_SIZE);
    {
        QWORD hash = 123;
        readCalls = 0;
        failReadCall = 1;
        ok = ok && ChecksumTextFile(path, &hash) == CHECKSUM_ERROR && hash == 123;
        failReadCall = 0;
    }
    if (!DeleteFile(path))
        return 0;
    _tcscpy_s(path, MAX_PATH, workdir);
    _tcscat_s(path, MAX_PATH, TEXT("\\extensionless"));
    ok = ok && TestTextFile(path, utf8, sizeof(utf8), CHECKSUM_OK, TEXT_SAMPLE_SIZE);
    if (!DeleteFile(path))
        return 0;
    if (!RemoveDirectory(workdir))
        return 0;
    for (i = 1; i < sizeof(textExtensions) / sizeof(textExtensions[0]); ++i)
        assert(_tcsicmp(textExtensions[i - 1], textExtensions[i]) < 0);
    return ok;
}

static int TestSize(LPCTSTR path, const unsigned char* data, DWORD size)
{
    DWORD written;
    QWORD actual = 0;
    HANDLE file = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }
    if (!WriteFile(file, data, size, &written, NULL) || written != size) {
        CloseHandle(file);
        return 0;
    }
    CloseHandle(file);
    readCalls = allocationCalls = 0;
    return ChecksumFromFile(path, &actual) && actual == ExpectedChecksum(data, size)
        && (size > 16 * 1024 || (readCalls == 1 && allocationCalls == 0))
        && (size <= 16 * 1024 || size > 256 * 1024 || readCalls == 2);
}

static BOOL LegacySmallChecksum(LPCTSTR path, QWORD* checksum)
{
    unsigned char buffer[256 * 1024], next;
    DWORD size, extra;
    HANDLE file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    BOOL success = FALSE;

    if (file == INVALID_HANDLE_VALUE)
        return FALSE;
    if (InitOnceExecuteOnce(&dispatchOnce, InitializeHashDispatch, NULL, NULL)
        && CountReadFile(file, buffer, sizeof(buffer), &size, NULL)
        && CountReadFile(file, &next, 1, &extra, NULL) && extra == 0) {
        *checksum = (QWORD)XXH3_64bits(buffer, size);
        success = TRUE;
    }
    CloseHandle(file);
    return success;
}

static int BenchmarkSmallFiles(LPCTSTR path, const unsigned char* data)
{
    const DWORD sizes[] = { 0, 4096, 16384 };
    LARGE_INTEGER frequency, start, end;
    size_t sizeIndex;
    int round, order, iteration;
    QWORD hash;

    if (!QueryPerformanceFrequency(&frequency))
        return 0;
    for (sizeIndex = 0; sizeIndex < sizeof(sizes) / sizeof(sizes[0]); ++sizeIndex) {
        LONGLONG elapsed[2] = { 0, 0 };
        QWORD expected = ExpectedChecksum(data, sizes[sizeIndex]);

        if (!TestSize(path, data, sizes[sizeIndex]))
            return 0;
        for (round = 0; round < 2; ++round) {
            // Alternate ABBA order to reduce cache and ordering bias.
            for (order = 0; order < 4; ++order) {
                int optimized = order == 1 || order == 2;

                if (!QueryPerformanceCounter(&start))
                    return 0;
                for (iteration = 0; iteration < 1000; ++iteration) {
                    BOOL success = optimized
                        ? ChecksumFromFile(path, &hash) : LegacySmallChecksum(path, &hash);
                    if (!success || hash != expected)
                        return 0;
                }
                if (!QueryPerformanceCounter(&end))
                    return 0;
                elapsed[optimized] += end.QuadPart - start.QuadPart;
            }
        }
        printf("Cached %lu-byte file, 4000 hashes: legacy %.2f ms, optimized %.2f ms\n",
            sizes[sizeIndex], elapsed[0] * 1000.0 / frequency.QuadPart,
            elapsed[1] * 1000.0 / frequency.QuadPart);
    }
    return 1;
}

int main(int argc, char** argv)
{
    TCHAR directory[MAX_PATH];
    TCHAR path[MAX_PATH];
    static unsigned char data[2 * 256 * 1024 + 19];
    DWORD i;
    QWORD hash;
    int ok;

    if (!GetTempPath(MAX_PATH, directory) || !GetTempFileName(directory, TEXT("xxh"), 0, path)) {
        return 1;
    }
    for (i = 0; i < sizeof(data); ++i) {
        data[i] = (unsigned char)(i * 37);
    }
    ok = TestSize(path, data, 0)
        && TestSize(path, data, 1)
        && TestSize(path, data, 7)
        && TestSize(path, data, 240)
        && TestSize(path, data, 241)
        && TestSize(path, data, 16 * 1024 - 1)
        && TestSize(path, data, 16 * 1024)
        && TestSize(path, data, 16 * 1024 + 1)
        && TestSize(path, data, 65536)
        && TestSize(path, data, 256 * 1024 - 1)
        && TestSize(path, data, 256 * 1024)
        && TestSize(path, data, 256 * 1024 + 1)
        && TestSize(path, data, sizeof(data));
    ok = ok && TestTextDetection(directory);
    for (failReadCall = 1; failReadCall <= 3; ++failReadCall) {
        readCalls = 0;
        hash = 123;
        ok = ok && !ChecksumFromFile(path, &hash) && hash == 123;
    }
    failReadCall = 0;
    failAllocation = TRUE;
    hash = 123;
    ok = ok && !ChecksumFromFile(path, &hash) && hash == 123;
    failAllocation = FALSE;
    if (argc == 2 && strcmp(argv[1], "--benchmark-small-files") == 0)
        ok = ok && BenchmarkSmallFiles(path, data);
    {
        HANDLE locked = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

        if (locked == INVALID_HANDLE_VALUE)
            return 1;
        hash = 123;
        ok = ok && !ChecksumFromFile(path, &hash) && hash == 123;
        CloseHandle(locked);
    }
    if (!DeleteFile(path)) {
        return 1;
    }
    ok = ok && !ChecksumFromFile(path, &hash);
    if (!ok) {
        fprintf(stderr, "Checksum test failed\n");
        return 1;
    }
    puts("Checksum test passed");
    return 0;
}
