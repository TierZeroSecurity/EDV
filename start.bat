@echo off
setlocal EnableDelayedExpansion
echo Starting EDV processes...
if not exist "out" (
    mkdir "out"
)
for /L %%i in (1,2,31) do (
    set "range=%%i"
    set /a next=%%i+1
    if !next! leq 31 (
        set "range=!range!,!next!"
    ) else (
        set "range=%%i"
    )
    echo Starting EDV.exe with range !range!...
    start /B "" EDV.exe SYNC_OR_ASYNC CHANGE_ME_WITH_A_VALID_conversationId !range! >> "out\output_%%i.txt" 2>> "out\error_%%i.txt"
    if errorlevel 1 (
        echo Error starting process for range !range!.
    ) else (
        echo Process for range !range! started.
    )
    timeout /t 1 /nobreak >nul
)

echo All processes started.
endlocal
