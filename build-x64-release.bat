@echo off
setlocal
pushd "%~dp0"

cmake --preset windows-x64
if errorlevel 1 goto :error

cmake --build --preset windows-x64-release
if errorlevel 1 goto :error

popd
exit /b 0

:error
set "build_error=%errorlevel%"
popd
exit /b %build_error%
