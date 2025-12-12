import socket
import threading
import csv
import os
from scapy.all import ARP, Ether, srp

from banner_detection import BannerDetector
from logger_config import ScannerLogger
from mac_vendor import MACVendorLookup

# Initialize global logger
scanner_log = ScannerLogger().get_logger()


class IoTScanner:

    def __init__(self):
        self.devices = []
        self.common_ports = [21, 22, 23, 80, 443, 8080]
        self.stop_scanning = False
        self.logger = scanner_log
        self.vendor_lookup = MACVendorLookup()
        self.banner_detector = BannerDetector()
        self.logger.debug("IoTScanner instance created")
        self.port_timeout = 0.5  # Default timeout
        self.max_threads = 50
        self.check_ssl = True
        self.check_default_creds = True
        self.check_banners = True
        self.check_weak_passwords = True

    def scan_network(self, ip_range="192.168.1.0/24"): # Default IP
        self.logger.info(f"Starting network scan on {ip_range}")
        self.devices.clear()

        try:
            # Validate IP range format
            if '/' not in ip_range:
                raise ValueError(f"Invalid IP range format: {ip_range}. Expected CIDR notation")

            # Create ARP request packet
            arp = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            self.logger.debug("Sending ARP packets...")
            result = srp(packet, timeout=2, verbose=0)[0]

            # Store device information with vendor lookup
            for sent, received in result:
                vendor_info = self.vendor_lookup.get_device_info(received.hwsrc)

                device_info = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': vendor_info['vendor'],
                    'device_type': vendor_info['device_type']
                }
                self.devices.append(device_info)
                self.logger.debug(f"Device found: {received.psrc} ({received.hwsrc}) - {vendor_info['vendor']}")

            self.logger.info(f"Network scan complete. Found {len(self.devices)} devices.")

        except ValueError as e:
            self.logger.error(f"Invalid IP range: {e}")
            raise
        except PermissionError as e:
            self.logger.error(f"Permission denied for network scan: {e}")
            self.logger.error("ARP scanning requires administrator/root privileges")
            raise PermissionError("Network scanning requires administrator/root privileges")
        except OSError as e:
            if e.errno == 19:
                self.logger.error(f"Network interface error: {e}")
                self.logger.error("Check your network connection and interface configuration")
            else:
                self.logger.error(f"Operating system error during network scan: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Network scan failed: {type(e).__name__}: {e}", exc_info=True)
            raise

    def scan_ports(self, device):
        open_ports = []
        ip = device['ip']
        self.logger.debug(f"Starting port scan on {ip}")

        for port in self.common_ports:
            if self.stop_scanning:
                self.logger.info(f"Port scan stopped by user for {ip}")
                break

            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                timeout = getattr(self, 'port_timeout', 0.5)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))

                if result == 0:
                    open_ports.append(port)
                    self.logger.debug(f"Port {port} OPEN on {ip}")
                else:
                    self.logger.debug(f"Port {port} closed on {ip}")

            except socket.timeout:
                self.logger.debug(f"Port {port} timeout on {ip}")
            except socket.gaierror as e:
                self.logger.error(f"Address resolution error for {ip}:{port} - {e}")
            except socket.error as e:
                if e.errno == 111:
                    self.logger.debug(f"Port {port} connection refused on {ip}")
                elif e.errno == 101:
                    self.logger.error(f"Network unreachable for {ip}:{port}")
                    break
                else:
                    self.logger.warning(f"Socket error on {ip}:{port} - errno {e.errno}: {e}")
            except OverflowError as e:
                self.logger.error(f"Invalid port number {port}: {e}")
            except Exception as e:
                self.logger.error(f"Unexpected error scanning {ip}:{port}: {e}", exc_info=True)
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception as e:
                        self.logger.debug(f"Error closing socket for {ip}:{port}: {e}")

        device['open_ports'] = open_ports
        if open_ports:
            self.logger.info(f"Port scan {ip} complete. Open ports: {open_ports}")
        else:
            self.logger.info(f"Port scan {ip} complete. No open ports found.")

    def enhanced_vulnerability_scan(self, device):
        ip = device['ip']
        open_ports = device.get('open_ports', [])

        if not open_ports:
            return

        self.logger.info(f"Starting enhanced vulnerability scan on {ip}")

        # Check if banner grabbing is enabled
        if not self.check_banners:
            self.logger.debug(f"Banner grabbing disabled, skipping detailed analysis for {ip}")
            device['services'] = []
            device['vulnerabilities'] = []
            device['risk_score'] = 0
            device['enhanced_severity'] = 'low'
            device['vulnerable'] = False
            return

        # Analyze all services on this device
        analysis = self.banner_detector.analyze_device(ip, open_ports)

        # Store detailed service information
        device['services'] = analysis['services']
        device['vulnerabilities'] = analysis['vulnerabilities']
        device['risk_score'] = analysis['risk_score']
        device['enhanced_severity'] = analysis['overall_severity']

        # Update legacy fields for compatibility
        device['vulnerable'] = len(analysis['vulnerabilities']) > 0

        # Log findings
        if analysis['vulnerabilities']:
            self.logger.warning(
                f"{ip}: Found {len(analysis['vulnerabilities'])} vulnerabilities (Risk Score: {analysis['risk_score']})")
            for vuln in analysis['vulnerabilities'][:3]:  # Log top 3
                self.logger.warning(f"  - [{vuln['severity'].upper()}] {vuln['name']}")
        else:
            self.logger.info(f"{ip}: No vulnerabilities detected")

        vendor = device.get('vendor', '').lower()
        vendor_specific_vulns = []

        if 'ring' in vendor:
            vendor_specific_vulns.append({
                'id': 'RING_DEVICE_01',
                'name': 'Ring Device Detected',
                'severity': 'medium',
                'description': 'Ring device - ensure firmware is up to date',
                'remediation': 'Check Ring app for firmware updates. Enable 2FA on Ring account.',
                'service': 'Vendor Detection',
                'port': 0
            })

        if 'espressif' in vendor:
            vendor_specific_vulns.append({
                'id': 'ESP_DEVICE_01',
                'name': 'ESP32/ESP8266 IoT Device',
                'severity': 'high',
                'description': 'DIY IoT device detected - often has default credentials',
                'remediation': 'Verify device configuration. Change any default passwords.',
                'service': 'Vendor Detection',
                'port': 0
            })

        if 'samsung' in vendor:
            vendor_specific_vulns.append({
                'id': 'SAMSUNG_DEVICE_01',
                'name': 'Samsung IoT Device',
                'severity': 'low',
                'description': 'Samsung device detected - verify SmartThings security',
                'remediation': 'Update Samsung firmware. Review SmartThings permissions.',
                'service': 'Vendor Detection',
                'port': 0
            })

        if 'amazon' in vendor:
            vendor_specific_vulns.append({
                'id': 'AMAZON_DEVICE_01',
                'name': 'Amazon Device Detected',
                'severity': 'low',
                'description': 'Amazon device (likely Echo/Alexa) detected',
                'remediation': 'Review Alexa privacy settings. Keep firmware updated.',
                'service': 'Vendor Detection',
                'port': 0
            })

        # Add vendor vulnerabilities to analysis
        analysis['vulnerabilities'].extend(vendor_specific_vulns)

    def assess_device(self, device):
        open_ports = device.get('open_ports', [])
        vulnerable = device.get('vulnerable', False)
        ip = device['ip']

        self.logger.debug(f"Assessing device {ip}")

        if vulnerable or 23 in open_ports:
            device['risk_level'] = "High"
            device['remediation'] = "Disable Telnet. Change default passwords. Update firmware immediately."
            self.logger.warning(f"HIGH risk device detected: {ip}")
        elif 80 in open_ports or 21 in open_ports:
            device['risk_level'] = "Medium"
            device['remediation'] = "Enable HTTPS/secure services. Restrict access to internal network."
            self.logger.warning(f"MEDIUM risk device detected: {ip}")
        elif open_ports:
            device['risk_level'] = "Low"
            device['remediation'] = "Close unnecessary ports. Monitor network activity."
            self.logger.info(f"LOW risk device detected: {ip}")
        else:
            device['risk_level'] = "Minimal"
            device['remediation'] = "No action needed."
            self.logger.info(f"MINIMAL risk device detected: {ip}")

    def run_full_scan(self, ip_range="192.168.1.0/24"): # Port Scanning & Vulnerability Assessment
        self.logger.info("=" * 60)
        self.logger.info("FULL NETWORK SCAN STARTED")
        self.logger.info(f"Target range: {ip_range}")
        self.logger.info("=" * 60)

        self.stop_scanning = False

        try:
            # Network discovery
            self.scan_network(ip_range)

            if not self.devices:
                self.logger.warning("No devices found on network")
                return

            # Port scanning with threading
            # Port scanning with threading
            self.logger.info(f"Starting port scans on {len(self.devices)} devices")
            from concurrent.futures import ThreadPoolExecutor, as_completed
            max_threads = getattr(self, 'max_threads', 50)

            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for device in self.devices:
                    if self.stop_scanning:
                        break
                    future = executor.submit(self.scan_ports, device)
                    futures.append(future)

                # Wait for all to complete
                for future in as_completed(futures):
                    if self.stop_scanning:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    try:
                        future.result()  # Get result or raise exception
                    except Exception as e:
                        self.logger.error(f"Port scan thread error: {e}")

            self.logger.info("All port scans complete")

            # Enhanced vulnerability scanning
            if not self.stop_scanning:
                self.logger.info("Starting enhanced vulnerability scanning")
                for device in self.devices:
                    if self.stop_scanning:
                        break
                    self.enhanced_vulnerability_scan(device)

            # Risk assessment
            if not self.stop_scanning:
                self.logger.info("Assessing device risks")
                for device in self.devices:
                    self.assess_device(device)

                self.logger.info("Risk assessment complete")

            # Summary
            self.logger.info("=" * 60)
            self.logger.info("FULL NETWORK SCAN COMPLETED")
            self.logger.info(f"Total devices analyzed: {len(self.devices)}")

            high_risk = sum(1 for d in self.devices if d.get('risk_level') == 'High')
            medium_risk = sum(1 for d in self.devices if d.get('risk_level') == 'Medium')
            self.logger.info(f"High risk devices: {high_risk}")
            self.logger.info(f"Medium risk devices: {medium_risk}")
            self.logger.info("=" * 60)

        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            self.stop_scanning = True
        except Exception as e:
            self.logger.error(f"Full scan failed: {e}", exc_info=True)
            raise

    def export_to_csv(self, filename):
        self.logger.info(f"Exporting results to CSV: {filename}")

        if not self.devices:
            self.logger.warning("No devices to export")
            raise ValueError("No scan results available. Please run a scan first.")

        try:
            if not filename.endswith('.csv'):
                filename += '.csv'

            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'IP Address', 'MAC Address', 'Vendor', 'Device Type',
                    'Open Ports', 'Services Detected', 'Vulnerabilities Count',
                    'Risk Score', 'Severity', 'Critical Issues', 'High Issues',
                    'Top Vulnerability', 'Remediation Priority'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for device in self.devices:
                    # Get services
                    services = device.get('services', [])
                    services_str = '; '.join([
                        f"{s.get('service', 'Unknown')} (port {s.get('port')})"
                        for s in services
                    ]) if services else 'None detected'

                    # Get vulnerabilities
                    vulns = device.get('vulnerabilities', [])
                    critical_vulns = [v for v in vulns if v['severity'] == 'critical']
                    high_vulns = [v for v in vulns if v['severity'] == 'high']

                    # Top vulnerability
                    top_vuln = 'None'
                    if critical_vulns:
                        top_vuln = critical_vulns[0]['name']
                    elif high_vulns:
                        top_vuln = high_vulns[0]['name']
                    elif vulns:
                        top_vuln = vulns[0]['name']

                    # Remediation priority
                    remediation = 'None'
                    if critical_vulns:
                        remediation = critical_vulns[0]['remediation']
                    elif high_vulns:
                        remediation = high_vulns[0]['remediation']

                    writer.writerow({
                        'IP Address': device.get('ip', 'Unknown'),
                        'MAC Address': device.get('mac', 'Unknown'),
                        'Vendor': device.get('vendor', 'Unknown'),
                        'Device Type': device.get('device_type', 'Unknown'),
                        'Open Ports': ', '.join(map(str, device.get('open_ports', []))),
                        'Services Detected': services_str,
                        'Vulnerabilities Count': len(vulns),
                        'Risk Score': device.get('risk_score', 0),
                        'Severity': device.get('enhanced_severity', 'Unknown').upper(),
                        'Critical Issues': len(critical_vulns),
                        'High Issues': len(high_vulns),
                        'Top Vulnerability': top_vuln,
                        'Remediation Priority': remediation
                    })

            self.logger.info(f"Export successful: {os.path.abspath(filename)}")
            return os.path.abspath(filename)

        except PermissionError as e:
            self.logger.error(f"Permission denied writing to {filename}: {e}")
            raise
        except IOError as e:
            self.logger.error(f"File I/O error during export: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Export failed: {e}", exc_info=True)
            raise