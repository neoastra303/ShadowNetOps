# Contributing to RedTeam Terminal

Thank you for your interest in contributing to RedTeam Terminal! We welcome contributions from the community and appreciate your help in making this project better.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## How Can I Contribute?

### Reporting Bugs
- Ensure the bug has not already been reported by searching existing [issues](https://github.com/your-username/redteam-terminal/issues)
- Use a clear and descriptive title for the issue
- Include detailed steps to reproduce the bug
- Provide information about your environment (OS, Python version, etc.)
- Explain the expected vs. actual behavior

### Suggesting Enhancements
- Search existing [issues](https://github.com/your-username/redteam-terminal/issues) to see if the enhancement has already been suggested
- Provide a clear and detailed explanation of the proposed enhancement
- Explain why this enhancement would be useful to users
- Consider the scope - is it a small change or a major feature?

### Pull Requests
- Fork the repository
- Create a new branch for your feature or bug fix (`git checkout -b feature/amazing-feature`)
- Make your changes following the style guide below
- Add or update tests if applicable
- Update documentation as needed
- Commit your changes (`git commit -m 'Add amazing feature'`)
- Push to your fork (`git push origin feature/amazing-feature`)
- Create a pull request to the `main` branch

## Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/redteam-terminal.git`
3. Navigate to the project directory: `cd redteam-terminal`
4. Create a virtual environment: `python -m venv venv`
5. Activate the virtual environment: 
   - On Windows: `venv\Scripts\activate`
   - On macOS/Linux: `source venv/bin/activate`
6. Install dependencies: `pip install -r requirements.txt`
7. Make your changes
8. Test your changes: `python redteam.py`

## Style Guides

### Python Style Guide
- Follow [PEP 8](https://pep8.org/) style guide
- Use 4 spaces for indentation (no tabs)
- Maximum line length of 88 characters
- Use descriptive variable and function names
- Add type hints where appropriate
- Include docstrings for all functions and classes

### Git Commit Messages
- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests if applicable

### Documentation Style
- Use clear and concise language
- Follow the existing documentation structure
- Include code examples where appropriate
- Document any breaking changes

## Testing

### Writing Tests
- Add tests for new features or bug fixes
- Follow the existing test structure
- Use descriptive names for test functions
- Test edge cases and error conditions

### Running Tests
- Before submitting a PR, ensure all tests pass
- Run the application to verify your changes work as expected

## Pull Request Process

1. Update the README.md with details of changes if applicable
2. Increase the version number in any examples files and the README.md if appropriate
3. Add your changes to [CHANGELOG.md](CHANGELOG.md) (if maintained)
4. Ensure your code follows the style guide
5. Wait for review and address any feedback

## Feature Requests

- Explain in detail how the feature should work
- Keep the scope as narrow as possible
- Remember that this is an open-source project maintained by volunteers

## Security Vulnerabilities

Please report security vulnerabilities responsibly by following our [Security Policy](SECURITY.md). Do not report security vulnerabilities through GitHub issues.

## Questions?

If you have questions about contributing, feel free to:
- Start a discussion in the [Discussions](https://github.com/your-username/redteam-terminal/discussions) tab
- Email us at support@redteam-terminal.com
- Join our community (when available)

Thank you for contributing to RedTeam Terminal!