# Network Security Scanner Tool

## Overview
A comprehensive network security assessment tool developed in Python for educational purposes as part of the ST4017CMD - Introduction to Programming module at Softwarica College of IT & E-Commerce.

## Features
- **Network Scanner**: Scan IP ranges to identify active hosts
- **Port Scanner**: Identify open ports and running services
- **Password Generator**: Generate secure random passwords
- **Password Strength Checker**: Evaluate password security
- **Message Encryption/Decryption**: Encrypt and decrypt messages using Caesar cipher
- **Vulnerability Scanner**: Basic web vulnerability detection

## Requirements
- Python 3.8 or higher
- No external dependencies (uses Python standard library only)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd network-security-scanner
```

2. Ensure Python 3.8+ is installed:
```bash
python --version
```

3. Run the application:
```bash
python network_security_scanner.py
```

## Usage

### Network Scanner
Scan a range of IP addresses to identify active hosts:
```
Select option 1
Enter base IP: 192.168.1
Enter start range: 1
Enter end range: 10
```

### Port Scanner
Scan for open ports on a target system:
```
Select option 2
Enter target: 192.168.1.1
Select scan type: 1 (Common ports) or 2 (Custom range)
```

### Password Generator
Generate secure random passwords:
```
Select option 3
Enter password length: 16
```

### Password Strength Checker
Evaluate the strength of existing passwords:
```
Select option 4
Enter password to check: YourPassword123!
```

### Message Encryption/Decryption
Encrypt or decrypt messages:
```
Select option 5
Choose operation: 1 (Encrypt) or 2 (Decrypt)
Enter message: Your secret message
Enter shift value: 3
```

### Vulnerability Scanner
Scan websites for common vulnerabilities:
```
Select option 6
Enter target URL: http://example.com
```

## Custom Data Structures
This project implements custom data structures and algorithms instead of relying solely on built-in Python structures:
- Custom scanning algorithms
- Manual implementation of Caesar cipher
- Custom password strength evaluation algorithm
- Custom network scanning logic

## Security Notice
This tool is for educational purposes only. Only use it on networks and systems you own or have explicit permission to test. Unauthorized network scanning and penetration testing is illegal.

## Academic Integrity
This project was developed as coursework for ST4017CMD module. All code is original work with proper citations for referenced algorithms and concepts.

## License
Educational use only - Softwarica College of IT & E-Commerce

## Author
[Your Name]
Student ID: [Your ID]
Module: ST4017CMD - Introduction to Programming
Institution: Softwarica College of IT & E-Commerce
Affiliation: Coventry University
