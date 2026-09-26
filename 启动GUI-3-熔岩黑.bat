@echo off
setlocal
title Peanut_WLYZ GUI - 熔岩黑

rem ============================================================
rem  Peanut_WLYZ GUI 启动器  ·  风格 3：熔岩黑
rem  纯黑硬朗底色 + 熔岩橙红强调 + 高对比直角卡片
rem
rem  用法:
rem    本脚本                以「熔岩黑」风格启动 GUI (Release)
rem    本脚本 server         同时确保本地 MockServer 在跑 (9001)
rem    本脚本 debug          启动 Debug 版本
rem    本脚本 server debug   调试版 + MockServer
rem ============================================================

cd /d "%~dp0"

set "SKIN=3"
set "SKINNAME=熔岩黑"
set "CFG=Release"
set "WANT_SERVER=0"

:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="debug"  set "CFG=Debug"
if /i "%~1"=="server" set "WANT_SERVER=1"
shift
goto parse_args
:args_done

set "APPDIR=%~dp0bin\%CFG%"
set "GUIEXE=%APPDIR%\PeanutGUI.exe"

echo --------------------------------------------
echo  Peanut_WLYZ GUI 启动器
echo  风格 : %SKIN% - %SKINNAME%
echo  配置 : %CFG%
echo  目录 : %APPDIR%
echo --------------------------------------------

if not exist "%GUIEXE%" goto no_gui

if not "%WANT_SERVER%"=="1" goto skip_server
netstat -ano -p tcp | findstr /r /c:":9001 .*LISTENING" >nul 2>&1
if not errorlevel 1 (echo [信息] 9001 端口已在监听, 跳过 MockServer& goto skip_server)
if not exist "%APPDIR%\PeanutMockServer.exe" (echo [警告] 找不到 PeanutMockServer.exe, 跳过& goto skip_server)
echo [信息] 启动本地 MockServer ^(127.0.0.1:9001^) ...
start "PeanutMockServer" /d "%APPDIR%" "%APPDIR%\PeanutMockServer.exe"
ping -n 2 127.0.0.1 >nul
:skip_server

echo [信息] 启动 GUI  ^(--skin=%SKIN%^)  ...
start "PeanutGUI-%SKINNAME%" /d "%APPDIR%" "%GUIEXE%" --skin=%SKIN%
echo [完成] GUI 已启动
exit /b 0

:no_gui
echo [错误] 找不到 %GUIEXE%
echo        请先编译项目:  powershell -File build_all.ps1
echo        或加 debug 参数启动 Debug 版本
echo.
pause
exit /b 1
