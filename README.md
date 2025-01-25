# GitSD - Git Source Disclosure Vulnerability Scanner

## Overview
GitSD is a Go-based tool designed to scan domains for Git source code disclosure vulnerabilities. It checks for exposed Git configuration and log files that might reveal sensitive project information.

## Features
- Scan multiple domains from a list
- Check for common Git-related exposed paths

## Prerequisites
- Go 1.x
- github.com/fatih/color package

## Installation
```bash
go install github.com/RHYru9/GitSD@latest
```

## Usage
```bash
Usage: gitsd <file containing list of domains>
```

### Example
```bash
gitsd urls.txt
```

## Scanned Paths
- /.git/
- /.git/index
- /.git/logs/
- /.git/HEAD
- /.git/logs/HEAD
- /.git/logs/refs
- /.git/logs/refs/remotes/origin/master

## Vulnerability Detection
The tool checks for specific signs of vulnerability:
- References containing "ref:"
- "index of" strings
- "initial commit" indicators
- "update by push" markers

## Output Colors
- Green: Vulnerable domains
- Yellow: Non-vulnerable or informational messages
- Red: Connection errors

## Disclaimer
Use only on domains you have permission to test. Unauthorized scanning may be illegal.
