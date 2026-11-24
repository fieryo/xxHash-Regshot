@echo off
setlocal
pushd "%~dp0"
cl /nologo /W4 /DUNICODE /D_UNICODE /Fe:checksum_test.exe checksum_test.c ^
  ..\HackerslangsRegShot\checksum.c ^
  ..\HackerslangsRegShot\third_party\xxhash\xxhash.c ^
  ..\HackerslangsRegShot\third_party\xxhash\xxh_x86dispatch.c
if errorlevel 1 exit /b 1
checksum_test.exe
set result=%errorlevel%
del /q checksum_test.exe checksum_test.obj checksum.obj xxhash.obj xxh_x86dispatch.obj
if not "%result%"=="0" exit /b %result%
cl /nologo /W4 /DUNICODE /D_UNICODE /Fe:fileenum_test.exe fileenum_test.c
if errorlevel 1 exit /b 1
fileenum_test.exe
set result=%errorlevel%
del /q fileenum_test.exe fileenum_test.obj
popd
exit /b %result%
