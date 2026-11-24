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
if not "%result%"=="0" exit /b %result%
cl /nologo /W4 /DUNICODE /D_UNICODE /Fe:usn_test.exe usn_test.c
if errorlevel 1 exit /b 1
usn_test.exe
set result=%errorlevel%
del /q usn_test.exe usn_test.obj
if not "%result%"=="0" exit /b %result%
cl /nologo /W4 /DUNICODE /D_UNICODE /Fe:usnbaseline_test.exe usnbaseline_test.c ^
  ..\HackerslangsRegShot\usnbaseline.c ^
  ..\HackerslangsRegShot\third_party\xxhash\xxhash.c
if errorlevel 1 exit /b 1
usnbaseline_test.exe
set result=%errorlevel%
del /q usnbaseline_test.exe usnbaseline_test.obj usnbaseline.obj xxhash.obj
if not "%result%"=="0" exit /b %result%
cl /nologo /W4 /DUNICODE /D_UNICODE /D_WINDOWS /Fe:snapshot_logic_test.exe ^
  snapshot_logic_test.c ^
  ..\HackerslangsRegShot\checksum.c ..\HackerslangsRegShot\fileenum.c ^
  ..\HackerslangsRegShot\language.c ..\HackerslangsRegShot\misc.c ^
  ..\HackerslangsRegShot\output.c ..\HackerslangsRegShot\setup.c ^
  ..\HackerslangsRegShot\ui.c ..\HackerslangsRegShot\winmain.c ..\HackerslangsRegShot\work.c ^
  ..\HackerslangsRegShot\usn.c ..\HackerslangsRegShot\usnbaseline.c ^
  ..\HackerslangsRegShot\third_party\xxhash\xxhash.c ^
  ..\HackerslangsRegShot\third_party\xxhash\xxh_x86dispatch.c ^
  /link advapi32.lib user32.lib shell32.lib comdlg32.lib gdi32.lib
if errorlevel 1 exit /b 1
snapshot_logic_test.exe
set result=%errorlevel%
del /q snapshot_logic_test.exe snapshot_logic_test.obj checksum.obj fileenum.obj language.obj misc.obj ^
  output.obj setup.obj ui.obj winmain.obj work.obj usn.obj usnbaseline.obj usnsnapshot.obj xxhash.obj xxh_x86dispatch.obj
popd
exit /b %result%
