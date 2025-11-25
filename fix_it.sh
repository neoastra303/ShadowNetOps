#!/bin/bash
# Shell script to run the fix issues command

echo "Running fix_issues.py script..."

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Python3 is not installed or not in PATH"
    exit 1
fi

# Check if required packages are installed
if ! python3 -c "import requests" &> /dev/null; then
    echo "Installing required packages..."
    pip3 install requests
fi

# Run the fix script
if [ $# -eq 0 ]; then
    echo "Usage: ./fix_it.sh [command] [options]"
    echo "Commands:"
    echo "  scan-only   - Scan for issues without fixing"
    echo "  fix-table   - Fix only table declaration issues"
    echo "  fix-all     - Fix all identified issues (default)"
    echo "Options:"
    echo "  --token GITHUB_TOKEN - GitHub token for creating issues"
    echo ""
    echo "Running fix-all by default..."
    python3 fix_issues.py --add-command fix-all
else
    case "$1" in
        scan-only)
            python3 fix_issues.py --add-command scan-only
            ;;
        fix-table)
            python3 fix_issues.py --add-command fix-table --token "$2"
            ;;
        fix-all)
            python3 fix_issues.py --add-command fix-all --token "$2"
            ;;
        *)
            echo "Invalid command. Use scan-only, fix-table, or fix-all"
            ;;
    esac
fi