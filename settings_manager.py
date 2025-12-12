# settings_manager.py
import json
import os
import tkinter as tk
from tkinter import ttk, messagebox


class ScanSettings:

    def __init__(self, config_file="scan_settings.json"):
        self.config_file = config_file
        self.settings = self.load_default_settings()
        self.load_settings()

    def load_default_settings(self):
        return {
            'scan_settings': {
                'timeout': 0.5,
                'max_threads': 50,
                'scan_speed': 'medium'
            },
            'ports': {
                'common': [21, 22, 23, 53, 80, 443, 8080],
                'iot_specific': [1883, 5683, 8883, 1900, 554, 502],
                'enabled_iot': True,
                'custom_ports': []
            },
            'vulnerability_checks': {
                'check_ssl': True,
                'check_default_creds': True,
                'check_banners': True,
                'check_weak_passwords': True
            },
            'reporting': {
                'auto_open_html': True,
                'include_low_severity': True,
                'detailed_logging': True
            }
        }

    def load_settings(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded = json.load(f)
                    # Merge with defaults to handle new settings
                    self._merge_settings(loaded)
                print(f"[*] Loaded settings from {self.config_file}")
            except Exception as e:
                print(f"[!] Error loading settings: {e}, using defaults")
        else:
            print("[*] No settings file found, using defaults")
            self.save_settings()

    def _merge_settings(self, loaded):
        for category, values in loaded.items():
            if category in self.settings:
                if isinstance(values, dict):
                    self.settings[category].update(values)
                else:
                    self.settings[category] = values

    def save_settings(self):
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
            print(f"[*] Settings saved to {self.config_file}")
            return True
        except Exception as e:
            print(f"[!] Error saving settings: {e}")
            return False

    def get_all_ports(self):
        ports = self.settings['ports']['common'].copy()

        if self.settings['ports']['enabled_iot']:
            ports.extend(self.settings['ports']['iot_specific'])

        if self.settings['ports']['custom_ports']:
            ports.extend(self.settings['ports']['custom_ports'])

        # Remove duplicates and sort
        return sorted(list(set(ports)))

    def get(self, category, key, default=None):
        try:
            return self.settings[category][key]
        except KeyError:
            return default


class SettingsWindow:

    def __init__(self, parent, settings_manager):
        self.parent = parent
        self.settings = settings_manager
        self.window = None

        # Store original settings in case user cancels
        self.original_settings = json.loads(json.dumps(settings_manager.settings))

    def show(self):
        self.window = tk.Toplevel(self.parent)
        self.window.title("Scanner Settings")
        self.window.geometry("600x700")
        self.window.resizable(False, False)

        # Center window
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() // 2) - (600 // 2)
        y = (self.window.winfo_screenheight() // 2) - (700 // 2)
        self.window.geometry(f"600x700+{x}+{y}")

        # Make modal
        self.window.transient(self.parent)
        self.window.grab_set()

        # Create notebook (tabbed interface)
        notebook = ttk.Notebook(self.window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create tabs
        self.create_scan_settings_tab(notebook)
        self.create_ports_tab(notebook)
        self.create_vulnerability_tab(notebook)

        # Buttons at bottom
        self.create_buttons()

        # Handle window close
        self.window.protocol("WM_DELETE_WINDOW", self.on_cancel)

    def create_scan_settings_tab(self, notebook):
        """Tab for general scan settings"""
        frame = ttk.Frame(notebook, padding=20)
        notebook.add(frame, text="Scan Settings")

        # Timeout setting
        ttk.Label(frame, text="Port Scan Timeout (seconds):", font=("Arial", 10)).pack(anchor=tk.W, pady=(0, 5))
        self.timeout_var = tk.DoubleVar(value=self.settings.settings['scan_settings']['timeout'])
        timeout_frame = ttk.Frame(frame)
        timeout_frame.pack(anchor=tk.W, pady=(0, 20))

        # Create scale with command to update label
        timeout_scale = ttk.Scale(timeout_frame, from_=0.1, to=3.0, variable=self.timeout_var,
                                  orient=tk.HORIZONTAL, length=300,
                                  command=lambda v: self.update_timeout_label())
        timeout_scale.pack(side=tk.LEFT)

        # Create formatted label
        self.timeout_label = ttk.Label(timeout_frame, text=f"{self.timeout_var.get():.1f}s")
        self.timeout_label.pack(side=tk.LEFT, padx=10)

        ttk.Label(frame, text="Lower = faster scan, might miss some ports\nHigher = slower scan, more reliable",
                  font=("Arial", 8), foreground="gray").pack(anchor=tk.W, pady=(0, 15))

        # Max threads
        ttk.Label(frame, text="Maximum Concurrent Threads:", font=("Arial", 10)).pack(anchor=tk.W, pady=(0, 5))
        self.threads_var = tk.IntVar(value=self.settings.settings['scan_settings']['max_threads'])
        threads_frame = ttk.Frame(frame)
        threads_frame.pack(anchor=tk.W, pady=(0, 20))

        # Create scale with command to update label
        threads_scale = ttk.Scale(threads_frame, from_=10, to=100, variable=self.threads_var,
                                  orient=tk.HORIZONTAL, length=300,
                                  command=lambda v: self.update_threads_label())
        threads_scale.pack(side=tk.LEFT)

        # Create formatted label
        self.threads_label = ttk.Label(threads_frame, text=str(self.threads_var.get()))
        self.threads_label.pack(side=tk.LEFT, padx=10)

        ttk.Label(frame, text="More threads = faster scan, but higher CPU usage",
                  font=("Arial", 8), foreground="gray").pack(anchor=tk.W, pady=(0, 15))

        # Scan speed preset
        ttk.Label(frame, text="Scan Speed Preset:", font=("Arial", 10)).pack(anchor=tk.W, pady=(0, 5))
        self.speed_var = tk.StringVar(value=self.settings.settings['scan_settings']['scan_speed'])
        speed_frame = ttk.Frame(frame)
        speed_frame.pack(anchor=tk.W, pady=(0, 10))
        ttk.Radiobutton(speed_frame, text="Fast (0.3s timeout, 100 threads)",
                        variable=self.speed_var, value="fast",
                        command=self.apply_speed_preset).pack(anchor=tk.W)
        ttk.Radiobutton(speed_frame, text="Medium (0.5s timeout, 50 threads)",
                        variable=self.speed_var, value="medium",
                        command=self.apply_speed_preset).pack(anchor=tk.W)
        ttk.Radiobutton(speed_frame, text="Thorough (1.5s timeout, 30 threads)",
                        variable=self.speed_var, value="thorough",
                        command=self.apply_speed_preset).pack(anchor=tk.W)

    def apply_speed_preset(self):
        speed = self.speed_var.get()
        presets = {
            'fast': {'timeout': 0.3, 'threads': 100},
            'medium': {'timeout': 0.5, 'threads': 50},
            'thorough': {'timeout': 1.5, 'threads': 30}
        }
        if speed in presets:
            self.timeout_var.set(presets[speed]['timeout'])
            self.threads_var.set(presets[speed]['threads'])
            # Update labels after setting values
            self.update_timeout_label()
            self.update_threads_label()

    def update_timeout_label(self):
        """Update timeout label with formatted value"""
        value = self.timeout_var.get()
        self.timeout_label.config(text=f"{value:.1f}s")

    def update_threads_label(self):
        """Update threads label with integer value"""
        value = int(self.threads_var.get())
        self.threads_label.config(text=str(value))

    def create_ports_tab(self, notebook):
        frame = ttk.Frame(notebook, padding=20)
        notebook.add(frame, text="Ports")

        # Common ports
        ttk.Label(frame, text="Common Ports (always scanned):",
                  font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(0, 5))
        common_text = tk.Text(frame, height=3, width=70, font=("Consolas", 9), wrap=tk.WORD)
        common_text.pack(fill=tk.X, pady=(0, 15))
        common_text.insert(1.0, ', '.join(map(str, self.settings.settings['ports']['common'])))
        self.common_ports_text = common_text

        # IoT-specific ports
        self.iot_enabled_var = tk.BooleanVar(value=self.settings.settings['ports']['enabled_iot'])
        iot_check = ttk.Checkbutton(frame, text="Enable IoT-Specific Ports",
                                    variable=self.iot_enabled_var,
                                    command=self.toggle_iot_ports)
        iot_check.pack(anchor=tk.W, pady=(0, 5))

        self.iot_frame = ttk.Frame(frame)
        self.iot_frame.pack(fill=tk.X, pady=(0, 15))

        iot_label = ttk.Label(self.iot_frame, text="IoT Ports (MQTT, CoAP, UPnP, RTSP, Modbus):",
                              font=("Arial", 9))
        iot_label.pack(anchor=tk.W)

        iot_text = tk.Text(self.iot_frame, height=3, width=70, font=("Consolas", 9), wrap=tk.WORD)
        iot_text.pack(fill=tk.X, pady=(5, 0))
        iot_text.insert(1.0, ', '.join(map(str, self.settings.settings['ports']['iot_specific'])))
        self.iot_ports_text = iot_text

        # Custom ports
        ttk.Label(frame, text="Custom Ports (optional, comma-separated):",
                  font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(10, 5))
        custom_text = tk.Text(frame, height=3, width=70, font=("Consolas", 9), wrap=tk.WORD)
        custom_text.pack(fill=tk.X, pady=(0, 5))
        custom_ports = self.settings.settings['ports']['custom_ports']
        if custom_ports:
            custom_text.insert(1.0, ', '.join(map(str, custom_ports)))
        self.custom_ports_text = custom_text

        ttk.Label(frame, text="Example: 3000, 5000, 9000",
                  font=("Arial", 8), foreground="gray").pack(anchor=tk.W)

        # Total ports info
        self.total_ports_label = ttk.Label(frame, text="", font=("Arial", 9, "bold"))
        self.total_ports_label.pack(anchor=tk.W, pady=(15, 0))
        self.update_total_ports()

        # Update button
        ttk.Button(frame, text="Update Port Count",
                   command=self.update_total_ports).pack(anchor=tk.W, pady=(10, 0))

        self.toggle_iot_ports()

    def toggle_iot_ports(self):
        if self.iot_enabled_var.get():
            for widget in self.iot_frame.winfo_children():
                widget.configure(state=tk.NORMAL)
        else:
            for widget in self.iot_frame.winfo_children():
                if isinstance(widget, tk.Text):
                    widget.configure(state=tk.DISABLED)
        self.update_total_ports()

    def update_total_ports(self):
        try:
            common = len(self.parse_port_list(self.common_ports_text.get(1.0, tk.END)))
            iot = len(self.parse_port_list(self.iot_ports_text.get(1.0, tk.END))) if self.iot_enabled_var.get() else 0
            custom = len(self.parse_port_list(self.custom_ports_text.get(1.0, tk.END)))
            total = common + iot + custom
            self.total_ports_label.config(text=f"Total ports to scan: {total}")
        except:
            self.total_ports_label.config(text="Invalid port format")

    def create_vulnerability_tab(self, notebook):
        frame = ttk.Frame(notebook, padding=20)
        notebook.add(frame, text="Vulnerability Checks")

        ttk.Label(frame, text="Enable/Disable Vulnerability Checks:",
                  font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(0, 15))

        # Checkboxes for each check
        self.ssl_var = tk.BooleanVar(value=self.settings.settings['vulnerability_checks']['check_ssl'])
        ttk.Checkbutton(frame, text="Check SSL/TLS Configuration",
                        variable=self.ssl_var).pack(anchor=tk.W, pady=5)

        self.creds_var = tk.BooleanVar(value=self.settings.settings['vulnerability_checks']['check_default_creds'])
        ttk.Checkbutton(frame, text="Check for Default Credentials",
                        variable=self.creds_var).pack(anchor=tk.W, pady=5)

        self.banners_var = tk.BooleanVar(value=self.settings.settings['vulnerability_checks']['check_banners'])
        ttk.Checkbutton(frame, text="Perform Banner Grabbing",
                        variable=self.banners_var).pack(anchor=tk.W, pady=5)

        self.weak_pass_var = tk.BooleanVar(value=self.settings.settings['vulnerability_checks']['check_weak_passwords'])
        ttk.Checkbutton(frame, text="Check for Weak Password Patterns",
                        variable=self.weak_pass_var).pack(anchor=tk.W, pady=5)

        ttk.Label(frame, text="\nNote: Disabling checks will make scans faster but less comprehensive.",
                  font=("Arial", 9), foreground="gray", wraplength=500).pack(anchor=tk.W, pady=(15, 0))

    def create_buttons(self):
        button_frame = ttk.Frame(self.window)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

        ttk.Button(button_frame, text="Save Settings",
                   command=self.on_save).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel",
                   command=self.on_cancel).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Reset to Defaults",
                   command=self.on_reset).pack(side=tk.LEFT)

    def parse_port_list(self, text):
        ports = []
        for item in text.split(','):
            try:
                port = int(item.strip())
                if 1 <= port <= 65535:
                    ports.append(port)
            except ValueError:
                continue
        return ports

    def on_save(self):
        try:
            # Update settings object
            self.settings.settings['scan_settings']['timeout'] = self.timeout_var.get()
            self.settings.settings['scan_settings']['max_threads'] = self.threads_var.get()
            self.settings.settings['scan_settings']['scan_speed'] = self.speed_var.get()

            # Parse ports
            self.settings.settings['ports']['common'] = self.parse_port_list(self.common_ports_text.get(1.0, tk.END))
            self.settings.settings['ports']['iot_specific'] = self.parse_port_list(self.iot_ports_text.get(1.0, tk.END))
            self.settings.settings['ports']['enabled_iot'] = self.iot_enabled_var.get()
            self.settings.settings['ports']['custom_ports'] = self.parse_port_list(
                self.custom_ports_text.get(1.0, tk.END))

            # Vulnerability checks
            self.settings.settings['vulnerability_checks']['check_ssl'] = self.ssl_var.get()
            self.settings.settings['vulnerability_checks']['check_default_creds'] = self.creds_var.get()
            self.settings.settings['vulnerability_checks']['check_banners'] = self.banners_var.get()
            self.settings.settings['vulnerability_checks']['check_weak_passwords'] = self.weak_pass_var.get()

            # Save to file
            if self.settings.save_settings():
                messagebox.showinfo("Settings Saved",
                                    "Settings saved successfully!\nChanges will apply to next scan.",
                                    parent=self.window)
                self.window.destroy()
            else:
                messagebox.showerror("Save Failed",
                                     "Failed to save settings to file.",
                                     parent=self.window)
        except Exception as e:
            messagebox.showerror("Error", f"Error saving settings: {e}", parent=self.window)

    def on_cancel(self):
        response = messagebox.askyesno("Confirm Cancel",
                                       "Discard changes to settings?",
                                       parent=self.window)
        if response:
            # Restore original settings
            self.settings.settings = self.original_settings
            self.window.destroy()

    def on_reset(self):  # Reset to default settings
        response = messagebox.askyesno("Reset Settings",
                                       "Reset all settings to defaults?",
                                       parent=self.window)
        if response:
            self.settings.settings = self.settings.load_default_settings()
            messagebox.showinfo("Reset Complete",
                                "Settings reset to defaults.\nClose and reopen settings to see changes.",
                                parent=self.window)