# Path Traverser

Path Traverser is a Python-based security tool for detecting path traversal vulnerabilities in web applications. It automates the process of testing various traversal encoding techniques and attempts to access sensitive files on Linux or Windows systems. (ATM this tool only works on GET requests)


## 🚀 Features
Scans with basic and advanced traversal techniques

Supports Windows and Linux sensitive file checks

Validates based on known file signatures

Supports verbose output and optional continuation after finding a vulnerable path

Allows manual targeting of custom file paths


## 📦 Requirements
Python 3.x

No external Python libraries required — uses only built-in modules.


## ⚙️ Usage
      - python3 path.py -i <IP> -p <PORT> -d <DIRECTORY> [options]

## 🔧 Required arguments:
-i, --ip – Target IP address

-p, --port – Target port number

-d, --directory – Vulnerable endpoint or directory path (e.g., /public/plugins/alertlist/)

)

## 🧩 Optional arguments:
--level 0|1 – Traversal encoding level:

0: Basic encoding (e.g., ../)

1: Advanced techniques (null bytes, unicode, mixed slashes, etc.)

-O, --os linux|windows – Target OS type for scanning common sensitive files

--continue-on-success – Continue testing even after finding a valid file

-v, --verbose – Print detailed request info for each attempt

## 🧪 Examples
### 🔍 Scan a Linux web app for common sensitive files:
      - python3 path.py -i 192.168.153.181 -p 3000 -d /public/plugins/alertlist/ -O linux --level 1 -v




