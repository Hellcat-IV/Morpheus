# Sentinel

Sentinel project is a python script which can provide first layer of security as a Code Audit.

## Features

- **Static Code Analysis**: Detect common security vulnerabilities in PHP code.
  - SQL Injection
  - Cross-Site Scripting
  - Local and Remote File Inclusion
  - Command Injection
  - Code Injection
  - Secrets Detection
  - Information Leak
  - Debug/Dev Mode
  - Path traversal

## Installation

1. Cloe the project:
    ```bash
    git clone https://github.com/Hellcat-IV/Morpheus.git
    cd Morpheus/VulnResearch/Scripts/php-auditor
    ```

2. Install dependencies:
    ```bash
    pip install colorama
    ```

## Usage

Run the auditor on a PHP project directory:
```bash
python3 sentinel.py file.php
```

## Roadmap
- [ ] Improve reporting format
- [ ] Add PDF report generation
- [ ] Add remediation suggestions
- [ ] Add more complex rules

## License

This project is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html).
