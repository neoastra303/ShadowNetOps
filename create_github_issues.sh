#!/bin/bash
# Script to create GitHub issues for fixed bugs
# Run this script to create issues for all fixed problems

echo "Creating GitHub issues for fixed bugs..."
echo ""

echo "[1/3] Creating issue for missing table declaration..."
gh issue create --title "Fix: Missing Table Declaration in osint_tools_menu()" \
  --body "**File:** redteam.py:178
**Severity:** Critical
**Status:** Fixed

**Description:**
Table object was referenced without being declared. The table initialization code was removed but table usage remained, causing NameError.

**Error:**
\`\`\`
NameError: name 'table' is not defined
\`\`\`

**Fix Applied:**
Added missing table declaration in osint_tools_menu() method:
\`\`\`python
table = Table(
    title=\"[bold cyan]OSINT Tools[/bold cyan]\",
    show_header=True,
    header_style=\"bold magenta\",
    border_style=\"cyan\",
    box=box.ROUNDED,
)
\`\`\`

**Lines Changed:** 175-184

**Impact:** High - This prevented the OSINT tools menu from loading" \
  --label "bug,fixed,critical"
echo ""

echo "[2/3] Creating issue for undefined variable..."
gh issue create --title "Fix: Undefined Variable 'target' in OSINT Tools" \
  --body "**File:** tools/osint_tools.py:414
**Severity:** High
**Status:** Fixed

**Description:**
Variable 'target' was used before being declared, causing potential UnboundLocalError when choice 9 (Image Reverse Search) was selected.

**Error:**
\`\`\`
UnboundLocalError: local variable 'target' referenced before assignment
\`\`\`

**Fix Applied:**
Initialized target variable at the beginning of conditional block:
\`\`\`python
target = None
if choice in [\"1\", \"2\", \"3\", \"4\"]:
    target = Prompt.ask(...)
\`\`\`

**Lines Changed:** 414

**Impact:** Medium - This caused crashes when selecting image reverse search option" \
  --label "bug,fixed,high-priority"
echo ""

echo "[3/3] Creating issue for unreachable code..."
gh issue create --title "Fix: Unreachable Code Block in OSINT Choice Handler" \
  --body "**File:** tools/osint_tools.py:439-440
**Severity:** Medium
**Status:** Fixed

**Description:**
Unreachable else block prevented choice 9 (Image Reverse Search) from executing properly.

**Problem:**
\`\`\`python
elif choice == \"9\":
    target = Prompt.ask(...)
else:
    return  # This prevented choice 9 from continuing
\`\`\`

**Fix Applied:**
Removed the unreachable else block to allow all choices to execute properly.

**Lines Changed:** 439-440

**Impact:** Medium - This prevented image reverse search feature from working" \
  --label "bug,fixed,code-quality"
echo ""

echo "================================================"
echo "All GitHub issues created successfully!"
echo "================================================"
echo ""
echo "You can view the issues at:"
gh repo view --web
