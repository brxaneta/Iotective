# IoTective - IoT Network Security Scanner
<img width="128" height="128" alt="Iotective" src="https://github.com/user-attachments/assets/c977700b-f784-400b-a8d5-ebd2e4fa8559" />

IoTective is a comprehensive and lightweight network security scanner designed to identify, analyze, and assess vulnerabilities in IoT devices on your local network. 
Built with Python and featuring an intuitive GUI, it helps security researchers, network administrators, and homeowners understand their network security posture.

## ⚠️ Legal Notice
**IMPORTANT:** This tool is designed for authorized security testing and educational purposes only. You must have explicit permission to scan any network. Unauthorized network scanning may violate:

- Computer Fraud and Abuse Act (CFAA) - 18 U.S.C. § 1030
- Electronic Communications Privacy Act (ECPA)
- State and local computer crime laws

**By using this tool, you accept full responsibility for your actions.**

## Features
### 🔍 Network Discovery

Automatic network detection - Identifies your local network range
ARP-based device discovery - Fast and reliable device enumeration
MAC address vendor identification - Automatically identifies device manufacturers

### 🔌 Port Scanning

Configurable port lists - Scan common, IoT-specific, or custom ports
Multi-threaded scanning - Fast, efficient port detection
Adjustable scan speed - Balance between speed and accuracy

### 🛡️ Vulnerability Detection

Service fingerprinting - Identifies running services and versions
Banner grabbing - Extracts service information for analysis
CVE cross-referencing - Links to known vulnerabilities
Pattern-based detection - Identifies common security issues:

Telnet services (critical)
Default credentials
Unencrypted protocols (FTP, HTTP)
Weak authentication
Open databases
UPnP exposure
IoT-specific vulnerabilities

### 📊 Risk Assessment

Color-coded severity levels - Critical, High, Medium, Low
Risk scoring system - Quantitative security posture measurement
Vendor-specific checks - Tailored warnings for Ring, ESP32, Samsung, Amazon devices
Remediation guidance - Actionable security recommendations

### 💾 Reporting

Real-time GUI output - Color-coded, detailed scan results
CSV export - Comprehensive vulnerability reports
Detailed logging - Full scan history with rotating logs
Security summary - Network-wide security statistics

### ⚙️ Customization

Configurable settings - Adjust timeouts, threads, and scan speed
Custom port lists - Define your own ports to scan
Toggle vulnerability checks - Enable/disable specific security tests
Persistent configuration - Settings saved between sessions

## 🚀 Quick Start
**Prerequisites**

- Python 3.8 or higher
- Administrator/Root privileges (required for ARP scanning)
- Windows, Linux, or macOS

**Installation**

1. Install dependencies
```
   pip install -r requirements.txt
```
2. Run the scanner
```
   python iot_scanner.py
```

## 📖 Usage
**Basic Workflow**

Launch IoTective with administrator/root privileges
Accept the legal disclaimer (required on first run)
Review detected network - The tool auto-detects your local network
Click "Start Scan" to begin the security assessment
Review results - Examine discovered devices and vulnerabilities
Export report - Save results as CSV for further analysis

**Configuration**
Click the ⚙️ Settings button to customize:

- Scan Settings
   - Timeout: 0.1s - 3.0s (lower = faster, higher = more reliable)
   - Max Threads: 10 - 100 (higher = faster, but more CPU intensive)
   - Scan Speed Presets: Fast, Medium, Thorough

- Port Configuration
   - Common Ports: 21, 22, 23, 53, 80, 443, 8080
   - IoT-Specific: 1883 (MQTT), 5683 (CoAP), 1900 (UPnP), 554 (RTSP)
   - Custom Ports: Add your own comma-separated list

- Vulnerability Checks
   - SSL/TLS Configuration
   - Default Credentials
   - Banner Grabbing
   = Weak Password Patterns

## Acknowledgments

Scapy - Powerful packet manipulation library
MAC Vendors API - MAC address vendor lookup service
NIST NVD - CVE vulnerability database
CISA - Cybersecurity guidance and best practices
Iotective Icon Attribute - <a href="https://www.flaticon.com/free-icons/detective" title="detective icons">Detective icons created by Freepik - Flaticon</a>
