#include "../xxHash-Regshot/checksum.h"
#include "../xxHash-Regshot/third_party/xxhash/xxhash.h"
#include <stdio.h>

static int readCalls, allocationCalls, failReadCall;
static BOOL failAllocation;

static QWORD ExpectedChecksum(const unsigned char* data, DWORD size)
{
    return (QWORD)XXH3_64bits(data, size);
}

static BOOL WINAPI CountReadFile(HANDLE file, LPVOID buffer, DWORD size,
    LPDWORD bytesRead, LPOVERLAPPED overlapped)
{
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
