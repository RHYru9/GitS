# 🕵️ GitSD - Git Source Disclosure Vulnerability Scanner

## 🌐 Overview
GitSD is a Go-based tool designed to scan domains for Git source code disclosure vulnerabilities. It checks for exposed Git configuration and log files that might reveal sensitive project information.

## ✨ Features
- 🔍 Scan a list of domains
- 🕸️ Check for common Git-related exposed paths

## 💻 Installation
```bash
go install github.com/RHYru9/GitSD@latest
```

## 🚀 Usage
```bash
Usage: gitsd <file containing list of domains>
```

### 📝 Example
```bash
gitsd urls.txt
```

## 🔬 Scanned Paths
- `/.git/`
- `/.git/index`
- `/.git/logs/`
- `/.git/HEAD`
- `/.git/logs/HEAD`
- `/.git/logs/refs`
- `/.git/logs/refs/remotes/origin/master`

## 🚨 Vulnerability Detection
The tool checks for specific signs of vulnerability:
- References containing "ref:"
- "index of" strings
- "initial commit" indicators
- "update by push" markers

## 🚧 Output Example
```
http://redacted.example.tld/.git/logs/HEAD - Error: Get "http://redacted.example.tld.git/logs/HEAD": dial tcp: lookup redacted.example.tld no such host 
http://redacted.test.tld//.git/logs/ found [/.git/logs/], but contains HTML - Not vulnerable 
http://redacted.vuln.tld/.git/HEAD found [/.git/HEAD] - Vulnerable 
[+] vuln: 1
[+] [redacted.vuln.tld]
```

## ⚠️ Disclaimer
**Use only on domains you have permission to test. Unauthorized scanning may be illegal.**
