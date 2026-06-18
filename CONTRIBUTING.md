# Contributing to Cisco Switch Docu-Crawler

Thank you for choosing to contribute to the Cisco Switch Docu-Crawler project! We welcome all contributions, including bug fixes, feature requests, documentation improvements, and refactoring.

Please read through these guidelines to ensure a smooth contribution process.

## Licensing Notice

By contributing to this repository, you agree to license your contribution under the **GNU Affero General Public License Version 3.0 (AGPL-3.0)**. Ensure you include the license header block on any new source files you introduce.

## Code of Conduct

All contributors are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please be respectful and collaborative.

## Getting Started

1. **Fork the Repository**: Create a personal fork on GitHub.
2. **Clone the Repo**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Cisco-Docu-Crawler.git
   cd Cisco-Docu-Crawler
   ```
3. **Set Up the Environment**:
   It is recommended to run the bootstrap scripts to ensure you have Python 3, Pip, and dependencies set up:
   * **Linux/macOS**: `./run.sh`
   * **Windows**: `.\run.bat` or `.\run.ps1`
4. **Create a Topic Branch**:
   ```bash
   git checkout -b feature/my-new-feature
   ```

## Development Guidelines

### 1. Maintain Light Touch Principle
The core design principle of this tool is **Read-Only / Non-Impacting** execution on target devices.
* **Never** execute commands that write configuration state (like `config term`, `write memory`, or modify parameters).
* Use the safest possible show commands.
* If adding compatibility for new devices, explicitly verify they are not impacted by the checks.

### 2. Code Quality & Formatting
* Keep your code clean, readable, and structured.
* Ensure all local modules are clean of unused imports.
* Run python compile checks before submitting:
  ```bash
  python3 -m py_compile cisco_crawler.py parser.py report_generator.py oui_lookup.py
  ```

### 3. Adding License Headers
All new `.py`, `.sh`, `.ps1`, and `.bat` files must begin with the standard AGPL 3.0 license header block:
```python
# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# ...
```

## How to Submit a Pull Request

1. Commit your changes locally. Make sure your commit messages are clear and follow standard conventions (e.g. `fix: resolve interface parsing regex crash`).
2. Push your topic branch to your fork.
3. Open a Pull Request from your branch to `main` of the main repository.
4. Describe the changes, the tests you performed, and the switches you validated against (e.g. Cisco Catalyst 2960, Nexus 9000, etc.).

## Contact / Help
If you have questions, feel free to open a GitHub Issue or contact the maintainer at **leifdavisson@gmail.com**.
