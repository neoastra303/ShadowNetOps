# Fix Commands Documentation

## Overview
This document describes the automated fix commands for the RedTeam Terminal project. These commands help identify, fix, and document issues in the codebase.

## Scripts

### fix_issues.py
Main script that identifies and fixes issues in the codebase.

#### Usage
```bash
python fix_issues.py [options]
```

#### Options
- `--token GITHUB_TOKEN`: GitHub token for creating issues automatically
- `--dry-run`: Run without making actual changes
- `--add-command`: Specify the command to run
  - `scan-only`: Scan for issues without fixing
  - `fix-table`: Fix only table declaration issues
  - `fix-all`: Fix all identified issues (default)

#### Examples
```bash
# Scan for issues without making changes
python fix_issues.py --dry-run

# Scan for issues only
python fix_issues.py --add-command scan-only

# Fix only table declaration issues
python fix_issues.py --add-command fix-table

# Fix all identified issues
python fix_issues.py --add-command fix-all

# Fix all issues and create GitHub issues
python fix_issues.py --add-command fix-all --token YOUR_GITHUB_TOKEN
```

### fix_it.bat
Windows batch script for easy execution of fix commands.

#### Usage
```cmd
fix_it.bat [command] [options]
```

#### Commands
- `scan-only`: Scan for issues without fixing
- `fix-table`: Fix only table declaration issues
- `fix-all`: Fix all identified issues (default)

#### Examples
```cmd
# Run with default settings (fix-all)
fix_it.bat

# Scan for issues
fix_it.bat scan-only

# Fix table issues with GitHub token
fix_it.bat fix-table YOUR_GITHUB_TOKEN
```

### fix_it.sh
Shell script for Unix-like systems (Linux/macOS).

#### Usage
```bash
./fix_it.sh [command] [options]
```

#### Commands
- `scan-only`: Scan for issues without fixing
- `fix-table`: Fix only table declaration issues
- `fix-all`: Fix all identified issues (default)

#### Examples
```bash
# Run with default settings (fix-all)
./fix_it.sh

# Scan for issues
./fix_it.sh scan-only

# Fix table issues with GitHub token
./fix_it.sh fix-table YOUR_GITHUB_TOKEN
```

## Features

### Issue Identification
- Automatically scans the codebase for common issues
- Currently detects missing table declarations in UI methods
- Extensible to detect additional issue types

### Automated Fixes
- Applies fixes automatically while preserving code formatting
- Creates backup files before making changes
- Validates fixes to ensure they work correctly

### GitHub Integration
- Creates GitHub issues for fixed problems
- Includes detailed descriptions of the fixes
- Adds appropriate labels to GitHub issues

### Documentation
- Updates FIXED_ISSUES.md with details of fixed issues
- Creates a fixed-it report with summary of fixes
- Maintains a chronological record of all fixes

## Supported Issues

### Current Issues Detected
1. Missing Table Declaration in UI methods
   - Issue: Table objects used without initialization
   - Location: Method where table.add_column or table.add_row appears before table initialization
   - Fix: Adds proper Table() initialization with styling

## Process Flow

1. **Scan Phase**: Identifies issues in the codebase
2. **Fix Phase**: Applies automated fixes to identified issues
3. **Documentation Phase**: Updates FIXED_ISSUES.md with fix details
4. **GitHub Phase**: Creates GitHub issues for fixed problems (if token provided)
5. **Reporting Phase**: Creates a fixed-it report summarizing all fixes

## Safety Features

- Backup files are created before modifications
- Dry-run mode available to preview changes
- Validation checks to prevent breaking changes
- Error handling with restoration from backup on failure