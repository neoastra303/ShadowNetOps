#!/usr/bin/env python3
"""
Script to identify and fix issues in the RedTeam Terminal codebase
Automatically generates GitHub issues for fixed problems
"""

import os
import subprocess
import json
import requests
from datetime import datetime
from typing import List, Dict, Any
import re
import sys


class IssueFixer:
    def __init__(self):
        self.fixed_issues = []
        
    def identify_issues(self) -> List[Dict[str, Any]]:
        """Identify issues in the codebase"""
        issues = []
        
        # Check for the table variable issue in redteam.py
        issues.extend(self.check_table_declaration_issue())
        
        # Add more issue checks here as needed
        return issues
    
    def check_table_declaration_issue(self) -> List[Dict[str, Any]]:
        """Check for missing table declaration in osint_tools_menu method"""
        issues = []
        file_path = "redteam.py"
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines):
                if "table.add_column" in line and "osint_tools_menu" in ''.join(lines[max(0, i-20):i+1]):
                    # Check if there's a table variable declaration before this line
                    method_start = max(0, i-50)  # Look up to 50 lines back
                    method_lines = lines[method_start:i]
                    
                    # Check if Table initialization exists before the add_column
                    table_initialized = False
                    for method_line in method_lines:
                        if "Table(" in method_line and ("table =" in method_line or "table= " in method_line):
                            table_initialized = True
                            break
                    
                    if not table_initialized:
                        issues.append({
                            "file": file_path,
                            "line": i + 1,
                            "issue_type": "critical",
                            "title": "Missing Table Declaration in redteam.py",
                            "description": "Table object was referenced without being declared. The table initialization was removed but usage remained.",
                            "severity": "Critical",
                            "method": "osint_tools_menu"
                        })
                        break
        
        except FileNotFoundError:
            print(f"File {file_path} not found")
        except Exception as e:
            print(f"Error checking {file_path}: {e}")
        
        return issues
    
    def fix_issues(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply fixes to identified issues"""
        fixed_issues = []
        
        for issue in issues:
            if issue["title"] == "Missing Table Declaration in redteam.py":
                if self.fix_table_declaration_issue(issue):
                    fixed_issues.append(issue)
        
        self.fixed_issues.extend(fixed_issues)
        return fixed_issues
    
    def fix_table_declaration_issue(self, issue: Dict[str, Any]) -> bool:
        """Fix the missing table declaration issue"""
        file_path = issue["file"]
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Make a backup before modifying
            with open(f"{file_path}.backup", 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            # Find the osint_tools_menu method and fix the missing table declaration
            method_start = -1
            method_end = -1
            
            for i, line in enumerate(lines):
                if "def osint_tools_menu" in line:
                    method_start = i
                elif method_start != -1 and line.strip().startswith("class ") and i > method_start:
                    method_end = i
                    break
                elif method_start != -1 and line.strip().startswith("def ") and i > method_start:
                    method_end = i
                    break
            
            if method_end == -1:  # If method goes to the end of file
                method_end = len(lines)
            
            # Look for the missing table initialization before the first table operation
            target_section = lines[method_start:method_end]
            insert_position = -1
            
            for i, line in enumerate(target_section):
                if "table.add_column" in line or "table.add_row" in line:
                    insert_position = i
                    break
            
            if insert_position != -1:
                # Insert the missing table initialization
                table_initialization = [
                    "        table = Table(\n",
                    "            title=\"[bold cyan]OSINT Tools[/bold cyan]\",\n",
                    "            show_header=True,\n",
                    "            header_style=\"bold magenta\",\n",
                    "            border_style=\"cyan\",\n",
                    "            box=box.ROUNDED,\n",
                    "        )\n",
                    "\n"
                ]
                
                # Insert the table initialization before the first table usage
                new_lines = lines[:method_start + insert_position]
                new_lines.extend(table_initialization)
                new_lines.extend(lines[method_start + insert_position:method_end])
                new_lines.extend(lines[method_end:])
                
                # Write the fixed content back to the file
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.writelines(new_lines)
                
                print(f"Fixed table declaration issue in {file_path}")
                return True
            else:
                print(f"Could not find exact location to fix table declaration in {file_path}")
                return False
        
        except Exception as e:
            print(f"Error fixing table declaration in {file_path}: {e}")
            # Restore from backup if something went wrong
            if os.path.exists(f"{file_path}.backup"):
                with open(f"{file_path}.backup", 'r', encoding='utf-8') as backup:
                    with open(file_path, 'w', encoding='utf-8') as orig:
                        orig.writelines(backup.readlines())
                os.remove(f"{file_path}.backup")
            return False
    
    def generate_github_issue(self, issue: Dict[str, Any], token: str = None) -> bool:
        """Generate a GitHub issue for the fixed problem"""
        try:
            # Read repository information
            repo_name = self.get_repo_name()
            if not repo_name:
                print("Could not determine repository name for GitHub issue creation")
                return False
            
            # Prepare issue data
            issue_title = f"Fix: {issue['title']}"
            issue_body = f"""
## Issue Fixed
**File:** {issue['file']}:{issue['line']}
**Severity:** {issue['severity']}
**Status:** Fixed
**Description:** {issue['description']}
**Fix Applied:** Added missing table declaration in {issue['method']} method.
**Lines Changed:** {issue['line']}-{issue['line']+10}

## Details
This issue was automatically detected and fixed by the fix_issues.py script.

## Affected Files
- {issue['file']}

## Resolution
The problem was resolved by ensuring proper variable initialization before usage.
"""
            
            # Create GitHub issue
            if token:
                headers = {
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json"
                }
                
                payload = {
                    "title": issue_title,
                    "body": issue_body,
                    "labels": ["bug", "automated-fix", "fixed"]
                }
                
                url = f"https://api.github.com/repos/{repo_name}/issues"
                
                response = requests.post(url, headers=headers, json=payload)
                
                if response.status_code in [201, 200]:
                    print(f"GitHub issue created successfully: {response.json()['html_url']}")
                    return True
                else:
                    print(f"Failed to create GitHub issue: {response.status_code} - {response.text}")
                    return False
            else:
                print(f"GitHub token not provided. Issue would have been created with title: {issue_title}")
                print("To create GitHub issues automatically, provide a GitHub token.")
                return False
        
        except Exception as e:
            print(f"Error generating GitHub issue: {e}")
            return False
    
    def get_repo_name(self) -> str:
        """Get the current repository name from git"""
        try:
            result = subprocess.run(["git", "remote", "-v"], capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            
            # Find the origin URL
            origin_line = None
            for line in lines:
                if "origin" in line and "(fetch)" in line:
                    origin_line = line
                    break
            
            if origin_line:
                # Extract URL from the line (format: origin  URL (fetch))
                url = origin_line.split()[1]
                # Extract repo name from URL (e.g., https://github.com/user/repo.git -> user/repo)
                if url.endswith('.git'):
                    url = url[:-4]
                return '/'.join(url.split('/')[-2:])
            
            return None
        except:
            return None
    
    def log_fixed_issue(self, issue: Dict[str, Any]):
        """Log the fixed issue to FIXED_ISSUES.md"""
        # Read the current FIXED_ISSUES.md
        fixed_issues_file = "FIXED_ISSUES.md"
        current_content = ""
        
        if os.path.exists(fixed_issues_file):
            with open(fixed_issues_file, 'r', encoding='utf-8') as f:
                current_content = f.read()
        
        # Find the next issue number
        issue_numbers = re.findall(r'## Issue (\d+):', current_content)
        next_issue_num = 1
        if issue_numbers:
            next_issue_num = max([int(num) for num in issue_numbers]) + 1
        
        # Create the new issue entry
        new_entry = f"""
## Issue {next_issue_num}: {issue['title']}
**File:** {issue['file']}:{issue['line']}
**Severity:** {issue['severity']}
**Status:** Fixed
**Description:** {issue['description']}
**Fix Applied:** Added missing table declaration in {issue['method']} method.
**Lines Changed:** {issue['line']}-{issue['line']+10}
"""
        
        # Append to the file
        with open(fixed_issues_file, 'a', encoding='utf-8') as f:
            f.write(new_entry)
        
        print(f"Fixed issue logged to {fixed_issues_file}")
    
    def run(self, github_token: str = None):
        """Run the full fix process"""
        print("🔍 Starting issue identification and fixing process...")
        
        # Identify issues
        issues = self.identify_issues()
        print(f"Found {len(issues)} issues to fix")
        
        if not issues:
            print("No issues found to fix")
            return
        
        # Fix issues
        fixed_issues = self.fix_issues(issues)
        print(f"Fixed {len(fixed_issues)} issues")
        
        # Generate GitHub issues and log to FIXED_ISSUES.md
        for issue in fixed_issues:
            # Generate GitHub issue if token provided
            if github_token:
                self.generate_github_issue(issue, github_token)
            
            # Log to FIXED_ISSUES.md
            self.log_fixed_issue(issue)
        
        # Create a fixed-it file
        self.create_fixed_it_file(fixed_issues)
        
        print("✅ Process completed!")
    
    def create_fixed_it_file(self, fixed_issues: List[Dict[str, Any]]):
        """Create a fixed-it file with details of fixes"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        content = f"""# Fixed It Report
Generated on: {timestamp}

## Summary
Total issues fixed: {len(fixed_issues)}

## Fixed Issues
"""
        
        for i, issue in enumerate(fixed_issues, 1):
            content += f"""
{i}. **Title:** {issue['title']}
   **File:** {issue['file']}
   **Line:** {issue['line']}
   **Severity:** {issue['severity']}
   **Description:** {issue['description']}
"""
        
        with open("fixed-it-report.txt", 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"Fixed-it report created: fixed-it-report.txt")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Automatically fix issues and create GitHub issues')
    parser.add_argument('--token', help='GitHub token for creating issues')
    parser.add_argument('--dry-run', action='store_true', help='Run without making actual changes')
    parser.add_argument('--add-command', help='Add a custom command to fix specific issues',
                       choices=['fix-table', 'fix-all', 'scan-only'], default='fix-all')
    parser.add_argument('--target-file', help='Target specific file for fixing')

    args = parser.parse_args()

    fixer = IssueFixer()

    if args.dry_run:
        print("Running in dry-run mode - no changes will be made")
        issues = fixer.identify_issues()
        print(f"Would fix {len(issues)} issues:")
        for issue in issues:
            print(f"  - {issue['title']} in {issue['file']}:{issue['line']}")
    else:
        if args.add_command == 'scan-only':
            issues = fixer.identify_issues()
            print(f"Found {len(issues)} issues:")
            for i, issue in enumerate(issues, 1):
                print(f"  {i}. {issue['title']} in {issue['file']}:{issue['line']}")
        elif args.add_command == 'fix-table':
            # Only fix the table issue specifically
            issues = fixer.check_table_declaration_issue()
            if issues:
                fixed = fixer.fix_issues(issues)
                print(f"Fixed {len(fixed)} table declaration issues")

                for issue in fixed:
                    if args.token:
                        fixer.generate_github_issue(issue, args.token)
                    fixer.log_fixed_issue(issue)

                fixer.create_fixed_it_file(fixed)
            else:
                print("No table declaration issues found")
        else:  # fix-all
            fixer.run(github_token=args.token)


if __name__ == "__main__":
    main()