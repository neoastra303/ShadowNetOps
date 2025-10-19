# Changelog

All notable changes to RedTeam Terminal will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.0] - 2025-01-03

### Added
- OSINT Tools category expanded with 9 different investigation methods:
  - Social Media Investigation
  - Username Search with Sherlock integration
  - Image Reverse Search functionality
  - Phone Number OSINT capabilities
- Dependency management system with automatic installation feature
- Installation prompts for missing tools with cross-platform support
- New Web Attack tools: Subdomain Scanner, Tech Stack Detection, HTTP Header Analysis, Wayback Machine Search
- New Wireless Attack tools: Wifite Automation, GPS Mapping info, Deauth Attack, Evil Twin AP
- New Forensics tools: File Hashing, Network Forensics, Registry Analysis, Timeline Analysis, Log Analysis

### Changed
- Improved UI with better formatting and error handling for Windows compatibility
- Enhanced Network Reconnaissance with multiple scan types (Port Scanning, Host Discovery, Banner Grabbing, OS Detection, Traceroute)
- Enhanced Vulnerability Assessment with multiple scan types (General, Nmap Scripts, SSL/TLS, Web, CVE Lookup)
- Improved dependency checking with installation options
- Fixed Unicode character compatibility issues for Windows systems

### Fixed
- Resolved Unicode encoding issues that caused crashes on Windows systems
- Improved error handling throughout all modules
- Enhanced input validation and security measures

### Security
- Added comprehensive legal disclaimers and ethical use guidelines
- Enhanced authorization verification system
- Improved consent prompting for all tools

## [2.0.0] - 2024-12-15

### Added
- Complete modular architecture with base tool system
- 10 major tool categories with multiple sub-options
- Professional UI with rich console formatting
- Configuration management system
- Legal and ethical compliance framework

### Changed
- Complete rewrite with modular architecture
- Enhanced security controls and logging
- Professional documentation and guides

### Security
- Added authorization verification for all tools
- Implemented consent prompting system
- Added comprehensive legal disclaimers

## [1.0.0] - 2024-06-20

### Added
- Initial release of RedTeam Terminal
- Basic network reconnaissance tools
- Vulnerability assessment module
- Password strength tester
- OSINT tools integration

[Unreleased]: https://github.com/your-username/redteam-terminal/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/your-username/redteam-terminal/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/your-username/redteam-terminal/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/your-username/redteam-terminal/releases/tag/v1.0.0