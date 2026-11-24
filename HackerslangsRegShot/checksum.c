/*
    Copyright 2026 Hackerslang

    This file is part of Regshot, distributed under the GNU Lesser
    General Public License, version 2.1 or later.
*/

#include "checksum.h"
#include "third_party/xxhash/xxh_x86dispatch.h"

static INIT_ONCE dispatchOnce = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK InitializeHashDispatch(PINIT_ONCE once, PVOID parameter, PVOID* context)
{
    static const unsigned char input[256] = { 0 };
    (void)once;
    (void)parameter;
    (void)context;
    (void)XXH3_64bits_dispatch(input, sizeof(input));
    return TRUE;
}

BOOL ChecksumFromFile(LPCTSTR filename, QWORD* checksum)
{
    unsigned char buffer[256 * 1024];
    unsigned char next;
    XXH3_state_t* state;
    HANDLE file;
    DWORD bytesRead;
    BOOL success = FALSE;

    file = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (!InitOnceExecuteOnce(&dispatchOnce, InitializeHashDispatch, NULL, NULL)) {
        CloseHandle(file);
        return FALSE;
    }
    if (!ReadFile(file, buffer, sizeof(buffer), &bytesRead, NULL)) {
        CloseHandle(file);
        return FALSE;
    }
    {
        DWORD extra;

        if (!ReadFile(file, &next, 1, &extra, NULL)) {
            CloseHandle(file);
            return FALSE;
        }
        if (extra == 0) {
            *checksum = (QWORD)XXH3_64bits(buffer, bytesRead);
            CloseHandle(file);
            return TRUE;
        }
    }
    state = XXH3_createState();
    if (state == NULL) {
        CloseHandle(file);
        return FALSE;
    }
    if (XXH3_64bits_reset(state) == XXH_OK
        && XXH3_64bits_update(state, buffer, bytesRead) == XXH_OK
        && XXH3_64bits_update(state, &next, 1) == XXH_OK) {
        while (ReadFile(file, buffer, sizeof(buffer), &bytesRead, NULL)) {
            if (bytesRead == 0) {
                *checksum = (QWORD)XXH3_64bits_digest(state);
                success = TRUE;
                break;
            }
            if (XXH3_64bits_update(state, buffer, bytesRead) != XXH_OK) {
                break;
            }
        }
    }
    XXH3_freeState(state);
    CloseHandle(file);
    return success;
}
