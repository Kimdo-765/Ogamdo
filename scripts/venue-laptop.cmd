@echo off
REM ---------------------------------------------------------------------------
REM  Double-clickable launcher for venue-laptop.ps1.
REM
REM  WHY THIS FILE EXISTS
REM
REM  Windows client defaults to ExecutionPolicy=Restricted, which blocks every
REM  .ps1 outright -- you meet PSSecurityException before the script runs a
REM  single line. And a .ps1 copied from a UNC path or a USB stick picks up a
REM  Zone.Identifier mark, which blocks it AGAIN under RemoteSigned even after
REM  the policy is loosened.
REM
REM  Both are handled HERE, per-run, instead of asking anyone to weaken their
REM  machine's policy permanently for one contest:
REM    * -ExecutionPolicy Bypass applies to this process only.
REM    * Unblock-File clears the zone mark on the script beside this launcher.
REM
REM  Deliberately NO auto-elevation. A relaunch-as-admin needs batch quoting
REM  that could not be verified on the machine this was written on, and
REM  unverified quoting that only runs at the venue is worse than one extra
REM  right-click. The script itself detects a non-elevated shell and says so.
REM ---------------------------------------------------------------------------
setlocal
set "HERE=%~dp0"
set "PS1=%HERE%venue-laptop.ps1"

REM cmd.exe cannot hold a UNC path as its working directory. Run from
REM \\wsl.localhost\... and it silently falls back to C:\Windows, so %~dp0 no
REM longer points where the files are.
echo %HERE% | findstr /b /c:"\\\\" >nul
if not errorlevel 1 (
  echo [x] This is running from a network path:
  echo     %HERE%
  echo     cmd.exe cannot use a UNC path as its working directory.
  echo     Copy venue-laptop.cmd AND venue-laptop.ps1 into a LOCAL folder
  echo     ^(e.g. C:\ogamdo\^) and run it from there.
  echo.
  pause
  exit /b 1
)

if not exist "%PS1%" (
  echo [x] venue-laptop.ps1 was not found next to this launcher.
  echo     Copy BOTH files to the laptop, keeping them in the same folder.
  echo.
  pause
  exit /b 1
)

net session >nul 2>&1
if errorlevel 1 (
  echo [!] Not running as Administrator.
  echo     Collection below still works. For -Setup ^(forwarding + NAT^),
  echo     close this and right-click venue-laptop.cmd - "Run as administrator".
  echo.
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "Unblock-File -LiteralPath '%PS1%' -ErrorAction SilentlyContinue"
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
echo.
pause
