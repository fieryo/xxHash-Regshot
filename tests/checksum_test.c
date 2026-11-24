#include "../HackerslangsRegShot/checksum.h"
#include "../HackerslangsRegShot/third_party/xxhash/xxhash.h"
#include <stdio.h>

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
    return ChecksumFromFile(path, &actual) && actual == XXH3_64bits(data, size);
}

int main(void)
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
        && TestSize(path, data, 65536)
        && TestSize(path, data, 256 * 1024 - 1)
        && TestSize(path, data, 256 * 1024)
        && TestSize(path, data, 256 * 1024 + 1)
        && TestSize(path, data, sizeof(data));
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
