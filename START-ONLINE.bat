@echo off
title Starford Portal - ONLINE
cd /d "%~dp0"

set "NODE_EXE="

rem 0. Your own Node.js folder next to this file
if exist "%~dp0node-v24.21.0-win-x64\node-v24.21.0-win-x64\node.exe" set "NODE_EXE=%~dp0node-v24.21.0-win-x64\node-v24.21.0-win-x64\node.exe"

rem 1. Node.js installed normally, or already on this computer's PATH (same as before)
if not defined NODE_EXE where node >nul 2>nul && set "NODE_EXE=node"

rem 2. A Node.js ZIP folder placed anywhere inside this folder (any name, any depth)
if not defined NODE_EXE for /f "delims=" %%F in ('dir /s /b "%~dp0node.exe" 2^>nul') do if not defined NODE_EXE set "NODE_EXE=%%F"

rem 2b. A Node.js folder on the Desktop (normal Desktop or OneDrive Desktop)
if not defined NODE_EXE for /f "delims=" %%F in ('dir /s /b "%USERPROFILE%\Desktop\node.exe" 2^>nul') do if not defined NODE_EXE set "NODE_EXE=%%F"
if not defined NODE_EXE if defined OneDrive for /f "delims=" %%F in ('dir /s /b "%OneDrive%\Desktop\node.exe" 2^>nul') do if not defined NODE_EXE set "NODE_EXE=%%F"

rem 3. Usual install places
if not defined NODE_EXE if exist "%ProgramFiles%\nodejs\node.exe" set "NODE_EXE=%ProgramFiles%\nodejs\node.exe"
if not defined NODE_EXE if exist "%LocalAppData%\Programs\nodejs\node.exe" set "NODE_EXE=%LocalAppData%\Programs\nodejs\node.exe"

rem 4. Ask once if it still cannot be found
if not defined NODE_EXE (
  echo.
  echo Node.js was not found automatically.
  echo Open the folder where you unzipped Node.js, find the file named node.exe,
  echo DRAG that file into this window, then press Enter.
  echo.
  set /p "NODE_EXE=node.exe: "
)
if not defined NODE_EXE goto nonode
set "NODE_EXE=%NODE_EXE:"=%"
"%NODE_EXE%" -v >nul 2>nul
if errorlevel 1 goto nonode
echo Using Node.js:
"%NODE_EXE%" -v

if not exist "%~dp0cloudflared.exe" (
  echo cloudflared.exe is missing. Put it in THIS folder, next to server.js.
  pause
  exit /b
)

rem Online mode: secure cookies (https) and trust the real visitor address sent by Cloudflare.
set "COOKIE_SECURE=1"
set "TRUST_PROXY=1"

rem AUTOMATIC SECOND BACKUP: remove the word "rem" at the start of the next line and put your own USB drive or folder.
rem set "BACKUP_COPY_DIR=E:\PortalBackup"

rem If Windows blocks saving in this folder, keep the data in a folder Windows always allows.
"%NODE_EXE%" -e "require('fs').mkdirSync(process.argv[1],{recursive:true})" "%~dp0data" >nul 2>nul
if errorlevel 1 set "DATA_DIR=%LocalAppData%\StarfordPortal\data"
if defined DATA_DIR echo NOTE: Windows does not allow saving in this folder. Data is kept in: %DATA_DIR%
echo Starting the portal in a second window...
start "Starford Portal Server" "%NODE_EXE%" server.js
timeout /t 5 >nul

echo.
echo ====================================================================
echo  Look below for a line like:  https://something-random.trycloudflare.com
echo  That is your portal's public address. Share THAT link.
echo  It changes every time you restart this window.
echo  Keep BOTH windows open while people use the portal.
echo ====================================================================
echo.
"%~dp0cloudflared.exe" tunnel --url http://localhost:3000
echo.
echo The online link has stopped. Press any key to close.
pause >nul
exit /b

:nonode
echo.
echo Node.js could not be started.
echo Put the unzipped Node.js folder inside THIS folder (next to server.js) and run this file again.
pause
exit /b
