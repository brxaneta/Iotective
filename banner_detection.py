import socket
import json
import os
from typing import Dict, List, Optional


class BannerDetector:

    def __init__(self, patterns_file="vulnerability_patterns.json"):
        self.patterns_file = patterns_file
        self.service_signatures = {}
        self.vulnerability_patterns = []
        self.severity_levels = {}
        self.load_patterns()
        self.check_ssl = True
        self.check_default_creds = True
        self.check_weak_passwords = True

    def load_patterns(self):
        if not os.path.exists(self.patterns_file):
            print(f"[!] Warning: {self.patterns_file} not found. Using basic detection only.")
            return

        try:
            with open(self.patterns_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.service_signatures = data.get('service_signatures', {})
                self.vulnerability_patterns = data.get('vulnerability_patterns', [])
                self.severity_levels = data.get('severity_levels', {})
            print(f"[*] Loaded {len(self.vulnerability_patterns)} vulnerability patterns")
        except Exception as e:
            print(f"[!] Error loading patterns: {e}")

    def grab_banner(self, ip: str, port: int, timeout: float = 2.0) -> Optional[str]:

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # For HTTP, send GET request to get more info
            if port in [80, 8080, 443, 8443]:
                try:
                    http_request = b"HEAD / HTTP/1.0\r\n\r\n"
                    sock.sendall(http_request)
                except:
                    pass

            # For FTP and SMTP, banner comes immediately
            # For others, might need to wait
            banner = sock.recv(4096)

            # Try multiple encoding methods
            for encoding in ['utf-8', 'latin-1', 'ascii']:
                try:
                    return banner.decode(encoding, errors='ignore')
                except:
                    continue

            # If all else fails, return hex representation
            return banner.hex()

        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except socket.error:
            return None
        except Exception as e:
            print(f"[!] Banner grab error on {ip}:{port}: {e}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass

    def identify_service(self, banner: str, port: int) -> Dict:

        if not banner:
            return {
                'service': 'Unknown',
                'version': None,
                'confidence': 'low',
                'details': 'No banner received'
            }

        banner_lower = banner.lower()

        # Check all service signatures
        for category, signatures in self.service_signatures.items():
            for sig in signatures:
                if sig['pattern'] in banner_lower and (sig.get('port') == port or sig.get('port') is None):
                    # Extract version if possible
                    version = self._extract_version(banner, sig['service'])

                    return {
                        'service': sig['service'],
                        'version': version,
                        'confidence': 'high',
                        'details': sig.get('description', ''),
                        'severity': sig.get('severity', 'low')
                    }

        # If no signature match, try generic port-based identification
        port_services = {
            21: 'FTP Server',
            22: 'SSH Server',
            23: 'Telnet Server',
            25: 'SMTP Server',
            80: 'HTTP Server',
            443: 'HTTPS Server',
            445: 'SMB/CIFS',
            3306: 'MySQL Database',
            5432: 'PostgreSQL Database',
            6379: 'Redis Database',
            8080: 'HTTP Proxy/Alt',
            1883: 'MQTT Broker',
            5683: 'CoAP Server',
            1900: 'UPnP Service'
        }

        if port in port_services:
            return {
                'service': port_services[port],
                'version': None,
                'confidence': 'medium',
                'details': f'Identified by port {port}',
                'severity': 'medium'
            }

        return {
            'service': 'Unknown Service',
            'version': None,
            'confidence': 'low',
            'details': f'Unidentified service on port {port}',
            'severity': 'low'
        }

    def _extract_version(self, banner: str, service_name: str) -> Optional[str]:
        import re

        # Common version patterns
        patterns = [
            r'(\d+\.\d+\.\d+)',  # x.y.z
            r'(\d+\.\d+)',  # x.y
            r'v(\d+\.\d+)',  # vx.y
            r'version (\d+\.\d+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def check_vulnerabilities(self, banner: str, port: int, service_info: Dict) -> List[Dict]:
        if not banner:
            return []

        banner_lower = banner.lower()
        vulnerabilities = []

        for vuln in self.vulnerability_patterns:
            # Skip certain checks based on settings
            if not self.check_default_creds and 'DEFAULT_CREDS' in vuln['id']:
                continue
            if not self.check_weak_passwords and 'WEAK' in vuln['id']:
                continue
            if not self.check_ssl and ('SSL' in vuln['id'] or 'CIPHER' in vuln['id']):
                continue

            # Check if any pattern matches
            for pattern in vuln['patterns']:
                if pattern in banner_lower:
                    vulnerabilities.append({
                        'id': vuln['id'],
                        'name': vuln['name'],
                        'severity': vuln['severity'],
                        'cve': vuln.get('cve'),
                        'description': vuln['description'],
                        'remediation': vuln['remediation'],
                        'matched_pattern': pattern,
                        'port': port,
                        'service': service_info.get('service', 'Unknown')
                    })
                    break  # Only count each vulnerability once

        # Sort by severity (critical first)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        vulnerabilities.sort(key=lambda x: severity_order.get(x['severity'], 4))

        return vulnerabilities

    def analyze_device(self, ip: str, open_ports: List[int]) -> Dict:
        results = {
            'ip': ip,
            'services': [],
            'vulnerabilities': [],
            'risk_score': 0,
            'overall_severity': 'low'
        }

        for port in open_ports:
            # NEW: Add port-based checks FIRST
            port_vulns = self.check_port_vulnerabilities(port)
            results['vulnerabilities'].extend(port_vulns)

            # Grab banner
            banner = self.grab_banner(ip, port)

            # Identify service
            service_info = self.identify_service(banner, port)
            service_info['port'] = port
            service_info['banner'] = banner[:200] if banner else None  # Truncate for storage

            results['services'].append(service_info)

            # Check for vulnerabilities
            if banner:
                vulns = self.check_vulnerabilities(banner, port, service_info)
                results['vulnerabilities'].extend(vulns)

        # Calculate overall risk score
        severity_scores = {
            'critical': 10,
            'high': 7,
            'medium': 5,
            'low': 2
        }

        total_score = 0
        for vuln in results['vulnerabilities']:
            total_score += severity_scores.get(vuln['severity'], 0)

        results['risk_score'] = total_score

        # Determine overall severity
        if total_score >= 10:
            results['overall_severity'] = 'critical'
        elif total_score >= 7:
            results['overall_severity'] = 'high'
        elif total_score >= 3:
            results['overall_severity'] = 'medium'
        else:
            results['overall_severity'] = 'low'

        return results

    def get_remediation_priority(self, vulnerabilities: List[Dict]) -> List[Dict]:

        if not vulnerabilities:
            return []

        # Group by severity
        critical = [v for v in vulnerabilities if v['severity'] == 'critical']
        high = [v for v in vulnerabilities if v['severity'] == 'high']
        medium = [v for v in vulnerabilities if v['severity'] == 'medium']
        low = [v for v in vulnerabilities if v['severity'] == 'low']

        priority_list = []

        if critical:
            priority_list.append({
                'priority': 1,
                'action': 'IMMEDIATE ACTION REQUIRED',
                'count': len(critical),
                'vulnerabilities': critical
            })

        if high:
            priority_list.append({
                'priority': 2,
                'action': 'Action required within 24 hours',
                'count': len(high),
                'vulnerabilities': high
            })

        if medium:
            priority_list.append({
                'priority': 3,
                'action': 'Action required within 1 week',
                'count': len(medium),
                'vulnerabilities': medium
            })

        if low:
            priority_list.append({
                'priority': 4,
                'action': 'Monitor and review',
                'count': len(low),
                'vulnerabilities': low
            })

        return priority_list


    def check_port_vulnerabilities(self, port: int) -> List[Dict]:
        vulnerabilities = []

        risky_ports = {
            23: {
                'name': 'Telnet Port Open',
                'severity': 'critical',
                'description': 'Telnet port 23 is open - transmits data in cleartext',
                'remediation': 'Close port 23. Use SSH (port 22) instead.'
            },
            445: {
                'name': 'SMB Port Exposed',
                'severity': 'high',
                'cve': 'CVE-2017-0144',
                'description': 'SMB port exposed - vulnerable to EternalBlue exploit',
                'remediation': 'Block port 445 from external access. Apply security patches.'
            },
            3389: {
                'name': 'RDP Port Open',
                'severity': 'high',
                'description': 'Remote Desktop Protocol exposed - common brute force target',
                'remediation': 'Use VPN for RDP access. Enable Network Level Authentication.'
            },
            5900: {
                'name': 'VNC Port Open',
                'severity': 'high',
                'description': 'VNC remote desktop accessible - often weak passwords',
                'remediation': 'Use SSH tunneling for VNC. Set strong password.'
            },
            1900: {
                'name': 'UPnP Service Exposed',
                'severity': 'high',
                'cve': 'CVE-2020-12695',
                'description': 'UPnP can be exploited for network attacks',
                'remediation': 'Disable UPnP if not needed. Restrict to internal network.'
            }
        }

        if port in risky_ports:
            vuln = risky_ports[port]
            vulnerabilities.append({
                'id': f'PORT_VULN_{port}',
                'name': vuln['name'],
                'severity': vuln['severity'],
                'cve': vuln.get('cve'),
                'description': vuln['description'],
                'remediation': vuln['remediation'],
                'matched_pattern': f'Port {port}',
                'port': port,
                'service': 'Port Detection'
            })

        return vulnerabilities