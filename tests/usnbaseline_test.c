#include "../xxHash-Regshot/usnbaseline.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void SetGuid(WCHAR* target, const char* text)
{
    size_t i;

    for (i = 0; text[i] != '\0'; ++i)
        target[i] = (WCHAR)text[i];
    target[i] = 0;
}

static USN_BASELINE_ENTRY Entry(DWORD volume, ULONGLONG fileId, ULONGLONG hash)
{
    USN_BASELINE_ENTRY entry;

    memset(&entry, 0, sizeof(entry));
    entry.volume = volume;
    entry.fileId = fileId;
    entry.size = 100;
    entry.writeTime = 200;
    entry.hash = hash;
    entry.attributes = 0x20;
    return entry;
}

static void TestRoundTripAndCorruption(void)
{
    USN_BASELINE_VOLUME volumes[2];
    USN_BASELINE_ENTRY entries[2];
    USN_BASELINE baseline, parsed;
    BYTE* data;
    DWORD size;

    memset(volumes, 0, sizeof(volumes));
    SetGuid(volumes[0].volumeGuid, "\\\\?\\Volume{a}\\");
    volumes[0].journalId = 7;
    volumes[0].checkpoint = 1000;
    volumes[0].volumeSerial = 0x1234;
    SetGuid(volumes[1].volumeGuid, "\\\\?\\Volume{b}\\");
    volumes[1].journalId = 8;
    entries[0] = Entry(0, 5, 55);
    entries[1] = Entry(1, 3, 33);
    baseline.volumes = volumes;
    baseline.volumeCount = 2;
    baseline.entries = entries;
    baseline.entryCount = 2;

    assert(UsnBaselineSerialize(&baseline, &data, &size));
    assert(UsnBaselineParse(data, size, &parsed));
    assert(parsed.volumeCount == 2 && parsed.entryCount == 2);
    assert(UsnBaselineFindVolume(&parsed, volumes[0].volumeGuid, 0x1234, 7) == 0);
    assert(UsnBaselineFindVolume(&parsed, volumes[0].volumeGuid, 0x1234, 9) == -1);
    assert(UsnBaselineFindVolume(&parsed, volumes[0].volumeGuid, 0x9999, 7) == -1);
    assert(UsnBaselineFind(&parsed, 0, 5)->hash == 55);
    assert(UsnBaselineFind(&parsed, 1, 3)->hash == 33);
    assert(UsnBaselineFind(&parsed, 0, 3) == NULL);
    UsnBaselineFree(&parsed);

    data[size - 1] ^= 1;
    assert(!UsnBaselineParse(data, size, &parsed));
    data[size - 1] ^= 1;
    assert(!UsnBaselineParse(data, size - 1, &parsed));
    data[0] = 'X';
    assert(!UsnBaselineParse(data, size, &parsed));
    free(data);

    entries[0] = Entry(1, 9, 1);
    assert(!UsnBaselineSerialize(&baseline, &data, &size));  /* unsorted */
    entries[0] = Entry(2, 1, 1);
    entries[1] = Entry(2, 2, 1);
    assert(!UsnBaselineSerialize(&baseline, &data, &size));  /* bad volume */
    entries[0] = Entry(0, 1, 1);
    entries[1] = Entry(1, 2, 1);
    volumes[1].volumeGuid[0] = 'C';
    assert(!UsnBaselineSerialize(&baseline, &data, &size));  /* bad GUID path */
    SetGuid(volumes[1].volumeGuid, "\\\\?\\Volume{a}\\");
    assert(!UsnBaselineSerialize(&baseline, &data, &size));  /* duplicate volume */
}

static void TestNormalize(void)
{
    USN_BASELINE_ENTRY entries[6];
    DWORD count = 6;

    entries[0] = Entry(0, 9, 1);
    entries[1] = Entry(0, 4, 2);
    entries[2] = Entry(0, 9, 1);   /* same hard link data: kept once */
    entries[3] = Entry(0, 7, 3);
    entries[4] = Entry(0, 7, 4);   /* conflicting data: dropped */
    entries[5] = Entry(0, 0, 5);   /* invalid ID: dropped */
    UsnBaselineNormalizeEntries(entries, &count);
    assert(count == 2);
    assert(entries[0].fileId == 4 && entries[1].fileId == 9);
}

static void TestChangeSet(void)
{
    USN_CHANGE_SET set;
    ULONGLONG i;

    memset(&set, 0, sizeof(set));
    assert(UsnChangeSetFlags(&set, 1) == 0);
    assert(UsnChangeSetAdd(&set, 1, FALSE, FALSE));
    assert(UsnChangeSetFlags(&set, 1) == USN_FILE_OPEN);
    assert(UsnChangeSetAdd(&set, 1, FALSE, TRUE));
    assert(UsnChangeSetFlags(&set, 1) == 0);
    assert(UsnChangeSetAdd(&set, 1, TRUE, TRUE));
    assert(UsnChangeSetFlags(&set, 1) == USN_FILE_CHANGED);
    assert(UsnChangeSetAdd(&set, 1, FALSE, FALSE));
    assert(UsnChangeSetFlags(&set, 1) == (USN_FILE_CHANGED | USN_FILE_OPEN));
    for (i = 2; i < 5000; ++i)
        assert(UsnChangeSetAdd(&set, i << 20, (i & 1) != 0, TRUE));
    assert(set.count == 4999);
    assert(UsnChangeSetFlags(&set, 1) == (USN_FILE_CHANGED | USN_FILE_OPEN));
    assert(UsnChangeSetFlags(&set, 3ULL << 20) == USN_FILE_CHANGED);
    assert(UsnChangeSetFlags(&set, 4ULL << 20) == 0);
    assert(UsnChangeSetFlags(&set, 5001ULL << 20) == 0);
    UsnChangeSetFree(&set);
}

static void TestReuseRules(void)
{
    USN_BASELINE_ENTRY entry = Entry(0, 5, 1);

    assert(UsnCanReuseHash(&entry, 0, 100, 200, 0x20));
    assert(!UsnCanReuseHash(NULL, 0, 100, 200, 0x20));
    assert(!UsnCanReuseHash(&entry, USN_FILE_CHANGED, 100, 200, 0x20));
    assert(!UsnCanReuseHash(&entry, USN_FILE_OPEN, 100, 200, 0x20));
    assert(!UsnCanReuseHash(&entry, 0, 101, 200, 0x20));
    assert(!UsnCanReuseHash(&entry, 0, 100, 201, 0x20));
    assert(!UsnCanReuseHash(&entry, 0, 100, 200, 0x21));
    entry.attributes = 0x420;
    assert(!UsnCanReuseHash(&entry, 0, 100, 200, 0x420));
    assert(UsnCanCacheHash(5, 0, 0x20));
    assert(UsnCanCacheHash(5, USN_FILE_CHANGED, 0x20));
    assert(!UsnCanCacheHash(5, USN_FILE_OPEN, 0x20));
    assert(!UsnCanCacheHash(0, 0, 0x20));
    assert(!UsnCanCacheHash(5, 0, 0x420));
}

int main(void)
{
    TestRoundTripAndCorruption();
    TestNormalize();
    TestChangeSet();
    TestReuseRules();
    puts("usnbaseline tests passed");
    return 0;
}
