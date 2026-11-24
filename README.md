# xxHash-Regshot
An improved version of Regshot with xxHash

File snapshots use the 64-bit XXH3 hash from xxHash 0.8.4. The upstream
x86 dispatcher selects AVX2 when supported, with a fallback on older CPUs.
XXH3 is non-cryptographic and is not suitable for security verification.

New hive files store hashes in file-content version 3. Older hive files
can still be loaded, but their file hashes are unknown, so comparisons
with them rely on file metadata. Hashing failures are written to the
Windows debugger output and likewise leave the hash unknown.

xxHash is distributed under the BSD 2-Clause license; see
`HackerslangsRegShot/third_party/xxhash/LICENSE`.

Run `tests\run-checksum-test.cmd` from a Visual Studio Developer Command
Prompt to test empty, binary, multi-buffer, and unreadable file hashing.
