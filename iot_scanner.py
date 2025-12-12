import sys
import threading
import tkinter as tk
from tkinter import messagebox, filedialog, ttk

from scanner_core import IoTScanner
from legal_disclaimer import LegalDisclaimerDialog
from settings_manager import ScanSettings, SettingsWindow


class ScannerGUI:
    def __init__(self, root, scanner, settings_manager):
        self.root = root
        self.scanner = scanner
        self.settings = settings_manager
        self.progress_bar = None
        self.setup_widgets()

    def get_local_network(self):
        import socket
        import ipaddress

        try:
            # Get the local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

            # Convert to /24 network (most common for home networks)
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            return str(network)
        except Exception as e:
            print(f"Error detecting network: {e}")
            return "192.168.1.0/24"  # Fallback default

    def setup_widgets(self):
        # Display detected network
        detected_network = self.get_local_network()
        info_frame = tk.Frame(self.root, bg="#e3f2fd", relief=tk.RIDGE, bd=2)
        info_frame.pack(pady=10, padx=10, fill=tk.X)

        tk.Label(info_frame, text="Detected Local Network:",
                 font=("Arial", 10), bg="#e3f2fd").pack(pady=5)
        tk.Label(info_frame, text=detected_network,
                 font=("Arial", 12, "bold"), fg="#2196f3", bg="#e3f2fd").pack(pady=5)

        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        # Action buttons
        tk.Button(button_frame, text="Start Scan", command=self.start_scan,
                  bg="#4caf50", fg="white", font=("Arial", 10, "bold"),
                  width=15, height=1).grid(row=0, column=0, padx=5)
        tk.Button(button_frame, text="Stop Scan", command=self.stop_scan,
                  bg="#ff9800", fg="white", font=("Arial", 10),
                  width=15, height=1).grid(row=0, column=1, padx=5)

        # Second row of buttons
        tk.Button(button_frame, text="Export Results", command=self.export_results,
                  bg="#2196f3", fg="white", font=("Arial", 10),
                  width=15, height=1).grid(row=1, column=0, padx=5, pady=5)
        tk.Button(button_frame, text="⚙ Settings", command=self.open_settings,
                  bg="#9c27b0", fg="white", font=("Arial", 10),
                  width=15, height=1).grid(row=1, column=1, padx=5, pady=5)

        progress_frame = tk.Frame(self.root)
        progress_frame.pack(pady=5, padx=10, fill=tk.X)

        self.progress_bar = ttk.Progressbar(
            progress_frame,
            mode='indeterminate',
            length=600
        )

        self.progress_label = tk.Label(
            progress_frame,
            text="Ready to scan",
            font=("Arial", 9),
            fg="#666666"
        )
        self.progress_label.pack(pady=2)

        # Progress bar hidden by default (pack_forget called later if needed)

        # Frame for output text and scrollbar
        output_frame = tk.Frame(self.root)
        output_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        # Scrollbar
        scrollbar = tk.Scrollbar(output_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.output_text = tk.Text(
            output_frame,
            height=20,
            width=90,
            font=("Consolas", 9),
            wrap=tk.WORD,
            yscrollcommand=scrollbar.set
        )
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.output_text.yview)

        self.output_text.tag_config("critical", foreground="#d32f2f", font=("Consolas", 9, "bold"))
        self.output_text.tag_config("high", foreground="#f57c00", font=("Consolas", 9, "bold"))
        self.output_text.tag_config("medium", foreground="#fbc02d", font=("Consolas", 9, "bold"))
        self.output_text.tag_config("low", foreground="#388e3c", font=("Consolas", 9, "bold"))
        self.output_text.tag_config("info", foreground="#2196f3")
        self.output_text.tag_config("success", foreground="#4caf50", font=("Consolas", 9, "bold"))
        self.output_text.tag_config("warning", foreground="#ff9800")
        self.output_text.tag_config("error", foreground="#f44336", font=("Consolas", 9, "bold"))
        self.output_text.tag_config("header", foreground="#1976d2", font=("Consolas", 10, "bold"))
        self.output_text.tag_config("device", foreground="#6a1b9a", font=("Consolas", 9, "bold"))

        # Welcome message with colors
        self.insert_colored("[✓] Legal disclaimer accepted\n", "success")
        self.insert_colored("[✓] Scanner ready for authorized use\n", "success")
        self.insert_colored(f"[✓] Settings loaded - Scanning {len(self.settings.get_all_ports())} ports\n", "success")
        self.output_text.insert(tk.END, "=" * 60 + "\n\n")

    def insert_colored(self, text, tag=None):
        start_pos = self.output_text.index("end-1c")
        self.output_text.insert(tk.END, text)
        if tag:
            end_pos = self.output_text.index("end-1c")
            self.output_text.tag_add(tag, start_pos, end_pos)
        self.output_text.see(tk.END)  # Auto-scroll

    def open_settings(self):
        settings_window = SettingsWindow(self.root, self.settings)
        settings_window.show()

        # After settings window closes, update the scanner
        self.root.after(100, self.apply_settings_to_scanner)

    def apply_settings_to_scanner(self):
        # Update scanner's port list and other settings
        self.scanner.common_ports = self.settings.get_all_ports()
        self.scanner.port_timeout = self.settings.get('scan_settings', 'timeout', 0.5)
        self.scanner.max_threads = self.settings.get('scan_settings', 'max_threads', 50)

        # Update vulnerability check settings
        self.scanner.check_ssl = self.settings.get('vulnerability_checks', 'check_ssl', True)
        self.scanner.check_default_creds = self.settings.get('vulnerability_checks', 'check_default_creds', True)
        self.scanner.check_banners = self.settings.get('vulnerability_checks', 'check_banners', True)
        self.scanner.check_weak_passwords = self.settings.get('vulnerability_checks', 'check_weak_passwords', True)

        # Also update banner detector settings
        self.scanner.banner_detector.check_ssl = self.scanner.check_ssl
        self.scanner.banner_detector.check_default_creds = self.scanner.check_default_creds
        self.scanner.banner_detector.check_weak_passwords = self.scanner.check_weak_passwords

        self.output_text.insert(tk.END,
                                f"\n[✓] Settings updated - Now scanning {len(self.scanner.common_ports)} ports\n")
        self.output_text.insert(tk.END,
                                f"[✓] Timeout: {self.scanner.port_timeout}s, Max threads: {self.scanner.max_threads}\n")

        # Show which checks are enabled
        checks_enabled = []
        if self.scanner.check_banners:
            checks_enabled.append("Banner Grabbing")
        if self.scanner.check_ssl:
            checks_enabled.append("SSL/TLS")
        if self.scanner.check_default_creds:
            checks_enabled.append("Default Creds")
        if self.scanner.check_weak_passwords:
            checks_enabled.append("Weak Passwords")

        if checks_enabled:
            self.output_text.insert(tk.END, f"[✓] Vulnerability checks: {', '.join(checks_enabled)}\n")
        else:
            self.output_text.insert(tk.END, f"[⚠] All vulnerability checks disabled - basic scan only\n")

    def start_scan(self):
        self.output_text.delete(1.0, tk.END)
        self.insert_colored("[*] Starting Authorized Scan...\n", "info")
        self.output_text.insert(tk.END, "=" * 60 + "\n")

        ip_range = self.get_local_network()
        self.insert_colored(f"[*] Scanning Network: {ip_range}\n", "info")
        self.output_text.insert(tk.END, "=" * 60 + "\n")

        self.progress_bar.pack(pady=5)
        self.progress_bar.start(10)
        self.progress_label.config(text="🔍 Scanning Network... Please Wait")

        # Run scan in separate thread to avoid freezing GUI
        scan_thread = threading.Thread(target=self.run_scan, args=(ip_range,), daemon=True)
        scan_thread.start()

    def stop_scan(self):
        self.scanner.stop_scanning = True
        self.output_text.insert(tk.END, "\n[!] Stopping scan...\n")

    def run_scan(self, ip_range):
        try:
            self.scanner.run_full_scan(ip_range)

            self.root.after(0, lambda: self.progress_bar.stop())
            self.root.after(0, lambda: self.progress_bar.pack_forget())
            self.root.after(0, lambda: self.progress_label.config(text="✓ Scan Complete"))

            self.display_results()
        except PermissionError:
            self.root.after(0, lambda: self.progress_bar.stop())
            self.root.after(0, lambda: self.progress_bar.pack_forget())
            self.insert_colored("\n[!] ERROR: Administrator/root privileges required\n", "error")
            self.insert_colored("[!] Please run as administrator or with sudo\n", "error")
        except ValueError as e:
            self.root.after(0, lambda: self.progress_bar.stop())
            self.root.after(0, lambda: self.progress_bar.pack_forget())
            self.insert_colored(f"\n[!] ERROR: {e}\n", "error")
        except Exception as e:
            self.root.after(0, lambda: self.progress_bar.stop())
            self.root.after(0, lambda: self.progress_bar.pack_forget())
            self.insert_colored(f"\n[!] ERROR: Scan failed - {e}\n", "error")

    def display_results(self):
        self.output_text.insert(tk.END, "\n" + "=" * 60 + "\n")
        self.insert_colored(f"[*] SCAN COMPLETE - Found {len(self.scanner.devices)} devices\n", "header")
        self.output_text.insert(tk.END, "=" * 60 + "\n\n")

        if not self.scanner.devices:
            self.insert_colored("[!] No devices found on network\n", "warning")
            return

        for i, device in enumerate(self.scanner.devices, 1):
            # Device header with color
            self.insert_colored(f"Device #{i}\n", "device")
            self.output_text.insert(tk.END, "-" * 50 + "\n")

            # Basic info
            self.output_text.insert(tk.END, f"IP Address:   {device['ip']}\n")
            self.output_text.insert(tk.END, f"MAC Address:  {device['mac']}\n")
            self.output_text.insert(tk.END, f"Vendor:       {device.get('vendor', 'Unknown')}\n")
            self.output_text.insert(tk.END, f"Device Type:  {device.get('device_type', 'Unknown')}\n")

            # Services detected
            services = device.get('services', [])
            if services:
                self.output_text.insert(tk.END, f"\nServices Detected ({len(services)}):\n")
                for svc in services:
                    service_name = svc.get('service', 'Unknown')
                    version = svc.get('version')
                    port = svc.get('port')

                    if version:
                        self.output_text.insert(tk.END, f"  • Port {port}: {service_name} v{version}\n")
                    else:
                        self.output_text.insert(tk.END, f"  • Port {port}: {service_name}\n")

                    if svc.get('confidence') != 'high':
                        self.output_text.insert(tk.END, f"    (Confidence: {svc.get('confidence', 'unknown')})\n")
            else:
                open_ports = device.get('open_ports', [])
                if open_ports:
                    self.output_text.insert(tk.END, f"\nOpen Ports:   {', '.join(map(str, open_ports))}\n")
                else:
                    self.output_text.insert(tk.END, "\nOpen Ports:   None\n")

            # ===== NEW: Color-coded vulnerabilities =====
            vulnerabilities = device.get('vulnerabilities', [])
            risk_score = device.get('risk_score', 0)

            if vulnerabilities:
                self.insert_colored(f"\n⚠ VULNERABILITIES FOUND: {len(vulnerabilities)} (Risk Score: {risk_score})\n",
                                    "warning")

                # Group by severity
                critical = [v for v in vulnerabilities if v['severity'] == 'critical']
                high = [v for v in vulnerabilities if v['severity'] == 'high']
                medium = [v for v in vulnerabilities if v['severity'] == 'medium']
                low = [v for v in vulnerabilities if v['severity'] == 'low']

                # Display critical first with RED color
                if critical:
                    self.insert_colored(f"\n  🔴 CRITICAL ({len(critical)}):\n", "critical")
                    for vuln in critical[:3]:
                        self.insert_colored(f"    - {vuln['name']}\n", "critical")
                        if vuln.get('cve'):
                            self.output_text.insert(tk.END, f"      CVE: {vuln['cve']}\n")

                # Display high with ORANGE color
                if high:
                    self.insert_colored(f"\n  🟠 HIGH ({len(high)}):\n", "high")
                    for vuln in high[:2]:
                        self.insert_colored(f"    - {vuln['name']}\n", "high")

                # Display medium with YELLOW color
                if medium:
                    self.insert_colored(f"\n  🟡 MEDIUM ({len(medium)}):\n", "medium")
                    for vuln in medium[:2]:
                        self.insert_colored(f"    - {vuln['name']}\n", "medium")

                # Display low with GREEN color
                if low:
                    self.insert_colored(f"\n  🟢 LOW ({len(low)})\n", "low")

                # Show top remediation action
                if critical or high:
                    top_vuln = critical[0] if critical else high[0]
                    self.insert_colored(f"\n  ⚡ Priority Action:\n", "warning")
                    self.output_text.insert(tk.END, f"    {top_vuln['remediation']}\n")
            else:
                self.insert_colored(f"\n✓ No vulnerabilities detected\n", "success")
            # ===== END NEW =====

            # Legacy risk info
            risk_level = device.get('risk_level', 'Unknown')
            remediation = device.get('remediation', 'None')

            # Color code risk level
            risk_color_map = {
                'High': 'critical',
                'Medium': 'medium',
                'Low': 'low',
                'Minimal': 'success'
            }
            risk_tag = risk_color_map.get(risk_level, None)

            self.output_text.insert(tk.END, "\nRisk Level:   ")
            self.insert_colored(f"{risk_level}\n", risk_tag)

            if remediation and remediation != "None" and remediation != "No action needed.":
                self.output_text.insert(tk.END, f"Remediation:  {remediation}\n")

            self.output_text.insert(tk.END, "\n")

        # Enhanced summary
        self._display_enhanced_summary()

    def _get_risk_indicator(self, severity):
        indicators = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }
        return indicators.get(severity, '⚪')

    def _display_enhanced_summary(self):
        self.output_text.insert(tk.END, "=" * 60 + "\n")
        self.output_text.insert(tk.END, "ENHANCED SECURITY SUMMARY\n")
        self.output_text.insert(tk.END, "=" * 60 + "\n")

        total_devices = len(self.scanner.devices)
        total_vulns = sum(len(d.get('vulnerabilities', [])) for d in self.scanner.devices)
        total_risk_score = sum(d.get('risk_score', 0) for d in self.scanner.devices)

        # Count by severity
        critical_devices = sum(1 for d in self.scanner.devices if d.get('enhanced_severity') == 'critical')
        high_devices = sum(1 for d in self.scanner.devices if d.get('enhanced_severity') == 'high')
        medium_devices = sum(1 for d in self.scanner.devices if d.get('enhanced_severity') == 'medium')
        low_devices = sum(1 for d in self.scanner.devices if d.get('enhanced_severity') == 'low')

        # Count vulnerability types
        all_vulns = []
        for d in self.scanner.devices:
            all_vulns.extend(d.get('vulnerabilities', []))

        critical_vulns = sum(1 for v in all_vulns if v['severity'] == 'critical')
        high_vulns = sum(1 for v in all_vulns if v['severity'] == 'high')

        self.output_text.insert(tk.END, f"Total Devices Scanned:     {total_devices}\n")
        self.output_text.insert(tk.END, f"Total Vulnerabilities:     {total_vulns}\n")
        self.output_text.insert(tk.END, f"Combined Risk Score:       {total_risk_score}\n")
        self.output_text.insert(tk.END, f"\nDevice Risk Distribution:\n")
        if critical_devices:
            self.insert_colored(f"  🔴 Critical Risk:        {critical_devices}\n", "critical")
        if high_devices:
            self.insert_colored(f"  🟠 High Risk:            {high_devices}\n", "high")
        if medium_devices:
            self.insert_colored(f"  🟡 Medium Risk:          {medium_devices}\n", "medium")
        if low_devices:
            self.insert_colored(f"  🟢 Low Risk:             {low_devices}\n", "low")

        self.output_text.insert(tk.END, f"\nVulnerability Breakdown:\n")
        if critical_vulns:
            self.insert_colored(f"  🔴 Critical:             {critical_vulns}\n", "critical")
        if high_vulns:
            self.insert_colored(f"  🟠 High:                 {high_vulns}\n", "high")

        # Calculate additional statistics
        if total_devices > 0:
            avg_risk_score = total_risk_score / total_devices

            self.output_text.insert(tk.END, f"\nStatistics:\n")
            self.output_text.insert(tk.END, f"  Average Risk per Device:   {avg_risk_score:.1f}\n")

            # Most common vulnerability
            if all_vulns:
                from collections import Counter
                vuln_names = [v['name'] for v in all_vulns]
                most_common = Counter(vuln_names).most_common(1)[0]
                self.output_text.insert(tk.END,
                                        f"  Most Common Vulnerability: {most_common[0]} ({most_common[1]} devices)\n")
        # Security posture
        if critical_devices > 0 or critical_vulns > 0:
            self.insert_colored(f"\n⚠ SECURITY POSTURE: CRITICAL - Immediate action required\n", "critical")
        elif high_devices > 0 or high_vulns > 0:
            self.insert_colored(f"\n⚠ SECURITY POSTURE: HIGH RISK - Action needed within 24 hours\n", "high")
        elif medium_devices > 0:
            self.insert_colored(f"\n✓ SECURITY POSTURE: MODERATE - Review and improve\n", "medium")
        else:
            self.insert_colored(f"\n✓ SECURITY POSTURE: GOOD - Continue monitoring\n", "success")

        self.output_text.insert(tk.END, "=" * 60 + "\n")


    def export_results(self):
        if not self.scanner.devices:
            messagebox.showwarning("No Results", "No scan results to export. Please run a scan first.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Scan Results"
        )

        if filename:
            try:
                filepath = self.scanner.export_to_csv(filename)
                messagebox.showinfo("Export Successful", f"Results exported to:\n{filepath}")
                self.output_text.insert(tk.END, f"\n[✓] Results exported to: {filepath}\n")
            except Exception as e:
                messagebox.showerror("Export Failed", f"Failed to export results:\n{e}")


def main():
    root = tk.Tk()
    root.title("IoTective")
    root.iconbitmap('iotective_icon.ico')
    root.geometry("800x650")

    # Make root window invisible during disclaimer
    root.geometry("0x0+0+0")
    root.attributes('-alpha', 0.0)
    root.update()

    # Show legal disclaimer
    disclaimer = LegalDisclaimerDialog(root)

    if not disclaimer.show_disclaimer():
        # User declined
        root.destroy()
        sys.exit(0)

    # User accepted - restore and show window
    root.attributes('-alpha', 1.0)
    root.geometry("800x700")
    root.deiconify()

    # Center the window on screen
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (800 // 2)
    y = (root.winfo_screenheight() // 2) - (700 // 2)
    root.geometry(f"800x700+{x}+{y}")

    # Initialize scanner and GUI
    settings_manager = ScanSettings()
    scanner = IoTScanner()
    scanner.common_ports = settings_manager.get_all_ports()
    scanner.port_timeout = settings_manager.get('scan_settings', 'timeout', 0.5)
    scanner.max_threads = settings_manager.get('scan_settings', 'max_threads', 50)

    # Initialize vulnerability check settings
    scanner.check_ssl = settings_manager.get('vulnerability_checks', 'check_ssl', True)
    scanner.check_default_creds = settings_manager.get('vulnerability_checks', 'check_default_creds', True)
    scanner.check_banners = settings_manager.get('vulnerability_checks', 'check_banners', True)
    scanner.check_weak_passwords = settings_manager.get('vulnerability_checks', 'check_weak_passwords', True)

    # Apply to banner detector
    scanner.banner_detector.check_ssl = scanner.check_ssl
    scanner.banner_detector.check_default_creds = scanner.check_default_creds
    scanner.banner_detector.check_weak_passwords = scanner.check_weak_passwords

    app = ScannerGUI(root, scanner, settings_manager)

    # Start application
    root.mainloop()


if __name__ == "__main__":
    main()