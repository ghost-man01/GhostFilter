# GhostFilter - Sensitive URL Filter Tool

**GhostFilter** is a lightweight, powerful tool designed to help security professionals and bug hunters filter sensitive URLs from large datasets. It is built using Go and supports multi-threaded processing to efficiently handle large lists of URLs. GhostFilter helps identify potential security vulnerabilities related to sensitive paths, API endpoints, configuration files, and more.

## Features

- **Customizable Keywords and Regex Filtering**: GhostFilter includes built-in keywords and regex patterns that target sensitive paths like login pages, admin panels, API endpoints, etc.
- **Multi-threaded Processing**: Take advantage of your machine’s CPU cores for faster URL processing.
- **Excludes File Types**: Automatically excludes common image file types (e.g., PNG, JPG, etc.) from being processed.
- **Simple Command-Line Interface**: Easy-to-use CLI with input and output file support.
- **Open Source**: Available for public use and contribution via GitHub.

## Installation

You can install **GhostFilter** globally using the `go install` command.

1. Ensure you have Go installed on your system (Go 1.16 or later is recommended).
2. Run the following command to install **GhostFilter**:

   ```bash
   go install github.com/ghost-man01/GhostFilter@latest

