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
   ```
3. After installation, you can use the ghostfilter command globally from your terminal.
###Usage
GhostFilter filters sensitive URLs from a file and outputs the result to another file.

###Command Syntax:
```bash
ghostfilter -i <input_file> -o <output_file>
```
- -i, --input: Path to the input file containing URLs to be filtered.
- -o, --output: Path to the output file where filtered sensitive URLs will be saved.
- -h, --help: Display the help message.

###Example Usage:

1. **Basic Example**: Filter URLs from urls.txt and save the results to filtered_urls.txt.

```bash
ghostfilter -i urls.txt -o filtered_urls.txt
```

2. **Help Message**: Show detailed usage information.

```bash
ghostfilter -h
```
###Keywords & Patterns
GhostFilter uses the following keywords and regex patterns to identify sensitive URLs:

- Keywords: admin, login, password, token, api, config, db, backup, etc.
- Regex Patterns: /admin\b, /auth\b, /token\b, etc.
You can customize these keywords and patterns in the main.go file to suit your specific needs.

###Contributing
Contributions are welcome! If you'd like to contribute to the project, feel free to open an issue or submit a pull request on [GitHub](https://github.com/ghost-man01/GhostFilter).

###How to Contribute:
1. Fork the repository
2. Create a new branch
3. Make your changes
4. Open a pull request with a clear description of your changes

###Contact
Developed by [Siddhant Shukla aka ghost__man01](https://linkedin.com/in/sid-d-hant)

For any questions, issues, or feature requests, please open an issue on the GitHub repository.
