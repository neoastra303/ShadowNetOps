@echo off
REM Batch script to run the fix issues command
echo Running fix_issues.py script...

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Check if required packages are installed
pip list | findstr "requests" >nul
if errorlevel 1 (
    echo Installing required packages...
    pip install requests
)

REM Run the fix script
if [%1] == [] (
    echo Usage: fix_it.bat [command] [options]
    echo Commands:
    echo   scan-only   - Scan for issues without fixing
    echo   fix-table   - Fix only table declaration issues
    echo   fix-all     - Fix all identified issues (default)
    echo Options:
    echo   --token GITHUB_TOKEN - GitHub token for creating issues
    echo.
    echo Running fix-all by default...
    python fix_issues.py --add-command fix-all
) else (
    if "%1" == "scan-only" (
        python fix_issues.py --add-command scan-only
    ) else if "%1" == "fix-table" (
        python fix_issues.py --add-command fix-table --token %2
    ) else if "%1" == "fix-all" (
        python fix_issues.py --add-command fix-all --token %2
    ) else (
        echo Invalid command. Use scan-only, fix-table, or fix-all
    )
)

pause