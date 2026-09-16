@echo off
setlocal enabledelayedexpansion
title Peanut_WLYZ - GUI Launcher

rem ============================================================
rem  Peanut_WLYZ GUI 快捷启动
rem  用法:
rem    启动GUI.bat              仅启动 GUI (默认, Release)
rem    启动GUI.bat server       同时确保本地 MockServer 在跑(端口 9001)
rem    启动GUI.bat debug        启动 Debug 版本
rem    启动GUI.bat server debug 调试版 + MockServer
rem ============================================================

rem -- 切到脚本所在目录 (项目根目录) --
cd /d "%~dp0"

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
set "SRVEXE=%APPDIR%\PeanutMockServer.exe"

echo --------------------------------------------
echo  Peanut_WLYZ GUI 启动器
echo  配置 : %CFG%
echo  目录 : %APPDIR%
echo --------------------------------------------

if not exist "%GUIEXE%" goto no_gui

if "%WANT_SERVER%"=="1" call :ensure_server

echo [信息] 启动 GUI ...
start "PeanutGUI" /d "%APPDIR%" "%GUIEXE%"
echo [完成] GUI 已启动
exit /b 0

rem ============================================================
rem  确保 MockServer 监听 127.0.0.1:9001
rem ============================================================
:ensure_server
call :port_listening
if not errorlevel 1 (
    echo [信息] 9001 端口已在监听, 跳过启动 MockServer
    exit /b 0
)
if not exist "%SRVEXE%" (
    echo [警告] 找不到 MockServer: %SRVEXE%
    echo         请先编译, 或手动启动服务端
    exit /b 0
)
echo [信息] 启动本地 MockServer ^(127.0.0.1:9001^) ...
start "PeanutMockServer" /d "%APPDIR%" "%SRVEXE%"
set /a _try=0
:wait_srv
set /a _try+=1
call :port_listening
if not errorlevel 1 (
    echo [信息] MockServer 已就绪
    exit /b 0
)
if !_try! geq 20 (
    echo [警告] 等待 MockServer 超时, 继续启动 GUI
    exit /b 0
)
ping -n 2 127.0.0.1 >nul 2>&1
goto wait_srv

rem ============================================================
rem  检测 9001 是否处于 LISTENING, 监听则 errorlevel=0
rem ============================================================
:port_listening
netstat -ano -p tcp | findstr /r /c:":9001 .*LISTENING" >nul 2>&1
exit /b %errorlevel%

:no_gui
echo [错误] 找不到 %GUIEXE%
echo        请先编译项目:  powershell -File build_all.ps1
echo        或改用 Debug 版本:  启动GUI.bat debug
echo.
pause
exit /b 1
