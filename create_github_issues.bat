@echo off
REM Script to create GitHub issues for fixed bugs
REM Run this script to create issues for all fixed problems

echo Creating GitHub issues for fixed bugs...
echo.

echo [1/3] Creating issue for missing table declaration...
gh issue create --title "Fix: Missing Table Declaration in osint_tools_menu()" --body "**File:** redteam.py:178%0A**Severity:** Critical%0A**Status:** Fixed%0A%0A**Description:**%0ATable object was referenced without being declared. The table initialization code was removed but table usage remained, causing NameError.%0A%0A**Error:**%0A```%0ANameError: name 'table' is not defined%0A```%0A%0A**Fix Applied:**%0AAdded missing table declaration in osint_tools_menu() method:%0A```python%0Atable = Table(%0A    title=\"[bold cyan]OSINT Tools[/bold cyan]\",%0A    show_header=True,%0A    header_style=\"bold magenta\",%0A    border_style=\"cyan\",%0A    box=box.ROUNDED,%0A)%0A```%0A%0A**Lines Changed:** 175-184%0A%0A**Impact:** High - This prevented the OSINT tools menu from loading" --label "bug,fixed,critical"
echo.

echo [2/3] Creating issue for undefined variable...
gh issue create --title "Fix: Undefined Variable 'target' in OSINT Tools" --body "**File:** tools/osint_tools.py:414%0A**Severity:** High%0A**Status:** Fixed%0A%0A**Description:**%0AVariable 'target' was used before being declared, causing potential UnboundLocalError when choice 9 (Image Reverse Search) was selected.%0A%0A**Error:**%0A```%0AUnboundLocalError: local variable 'target' referenced before assignment%0A```%0A%0A**Fix Applied:**%0AInitialized target variable at the beginning of conditional block:%0A```python%0Atarget = None%0Aif choice in [\"1\", \"2\", \"3\", \"4\"]:%0A    target = Prompt.ask(...)%0A```%0A%0A**Lines Changed:** 414%0A%0A**Impact:** Medium - This caused crashes when selecting image reverse search option" --label "bug,fixed,high-priority"
echo.

echo [3/3] Creating issue for unreachable code...
gh issue create --title "Fix: Unreachable Code Block in OSINT Choice Handler" --body "**File:** tools/osint_tools.py:439-440%0A**Severity:** Medium%0A**Status:** Fixed%0A%0A**Description:**%0AUnreachable else block prevented choice 9 (Image Reverse Search) from executing properly.%0A%0A**Problem:**%0A```python%0Aelif choice == \"9\":%0A    target = Prompt.ask(...)%0Aelse:%0A    return  # This prevented choice 9 from continuing%0A```%0A%0A**Fix Applied:**%0ARemoved the unreachable else block to allow all choices to execute properly.%0A%0A**Lines Changed:** 439-440%0A%0A**Impact:** Medium - This prevented image reverse search feature from working" --label "bug,fixed,code-quality"
echo.

echo ================================================
echo All GitHub issues created successfully!
echo ================================================
echo.
echo You can view the issues at:
gh repo view --web
