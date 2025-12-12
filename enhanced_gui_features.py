import tkinter as tk
from tkinter import ttk

class ColoredTextWidget:

    def __init__(self, parent, **kwargs):
        self.text_widget = tk.Text(parent, **kwargs)

        # Define color tags for different severity levels
        self.text_widget.tag_config("critical", foreground="#d32f2f", font=("Consolas", 9, "bold"))
        self.text_widget.tag_config("high", foreground="#f57c00", font=("Consolas", 9, "bold"))
        self.text_widget.tag_config("medium", foreground="#fbc02d", font=("Consolas", 9, "bold"))
        self.text_widget.tag_config("low", foreground="#388e3c", font=("Consolas", 9, "bold"))
        self.text_widget.tag_config("info", foreground="#2196f3")
        self.text_widget.tag_config("success", foreground="#4caf50", font=("Consolas", 9, "bold"))
        self.text_widget.tag_config("warning", foreground="#ff9800")
        self.text_widget.tag_config("error", foreground="#f44336", font=("Consolas", 9, "bold"))
        self.text_widget.tag_config("header", foreground="#1976d2", font=("Consolas", 10, "bold"))
        self.text_widget.tag_config("device_name", foreground="#6a1b9a", font=("Consolas", 9, "bold"))

    def insert_colored(self, text, color_tag=None):
        if color_tag:
            start_pos = self.text_widget.index("end-1c")
            self.text_widget.insert(tk.END, text)
            end_pos = self.text_widget.index("end-1c")
            self.text_widget.tag_add(color_tag, start_pos, end_pos)
        else:
            self.text_widget.insert(tk.END, text)

        # Auto-scroll to bottom
        self.text_widget.see(tk.END)

    def insert(self, index, text, tags=None):
        self.text_widget.insert(index, text, tags)

    def delete(self, start, end):
        self.text_widget.delete(start, end)

    def pack(self, **kwargs):
        self.text_widget.pack(**kwargs)

    def grid(self, **kwargs):
        self.text_widget.grid(**kwargs)


class ScanProgressBar:

    def __init__(self, parent):
        self.frame = ttk.Frame(parent)

        # Progress bar
        self.progress = ttk.Progressbar(
            self.frame,
            mode='indeterminate',
            length=400
        )
        self.progress.pack(pady=5)

        # Status label
        self.status_label = ttk.Label(
            self.frame,
            text="Ready to scan",
            font=("Arial", 9)
        )
        self.status_label.pack(pady=5)

        # Hide by default
        self.frame.pack_forget()

    def start(self, status_text="Scanning..."):
        self.status_label.config(text=status_text)
        self.frame.pack(pady=5, padx=10, fill=tk.X)
        self.progress.start(10)  # Update every 10ms

    def update_status(self, status_text):
        self.status_label.config(text=status_text)

    def stop(self):
        self.progress.stop()
        self.frame.pack_forget()

    def set_determinate(self, maximum):
        self.progress.config(mode='determinate', maximum=maximum, value=0)

    def set_progress(self, value):
        self.progress['value'] = value


# Helper functions
class ColoredOutputHelper:

    @staticmethod
    def format_severity(severity):
        severity_map = {
            'critical': ('🔴', 'critical'),
            'high': ('🟠', 'high'),
            'medium': ('🟡', 'medium'),
            'low': ('🟢', 'low')
        }
        return severity_map.get(severity.lower(), ('⚪', None))

    @staticmethod
    def format_device_header(device_num):
        return f"\n{'=' * 50}\nDevice #{device_num}\n{'=' * 50}\n"

    @staticmethod
    def format_vulnerability(vuln_name, severity):
        emoji, color = ColoredOutputHelper.format_severity(severity)
        return f"  {emoji} {vuln_name}\n", color


# Demo/Test Code
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Color Text & Progress Bar Demo")
    root.geometry("700x500")

    # Create colored text widget
    colored_text = ColoredTextWidget(root, height=20, width=80, font=("Consolas", 9))
    colored_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

    # Create progress bar
    progress_bar = ScanProgressBar(root)

    # Demo content
    colored_text.insert_colored("=== IoT Scanner Output Demo ===\n\n", "header")
    colored_text.insert_colored("[✓] Scanner initialized\n", "success")
    colored_text.insert_colored("[*] Starting scan...\n", "info")

    colored_text.insert_colored("\n--- Device #1 ---\n", "device_name")
    colored_text.insert_colored("IP: 192.168.1.100\n")
    colored_text.insert_colored("Vendor: Ring LLC\n")

    colored_text.insert_colored("\n⚠ VULNERABILITIES FOUND:\n", "warning")
    colored_text.insert_colored("  🔴 CRITICAL: ", "critical")
    colored_text.insert_colored("Telnet Service Active\n")
    colored_text.insert_colored("  🟠 HIGH: ", "high")
    colored_text.insert_colored("Default Credentials Detected\n")
    colored_text.insert_colored("  🟡 MEDIUM: ", "medium")
    colored_text.insert_colored("Unencrypted HTTP\n")
    colored_text.insert_colored("  🟢 LOW: ", "low")
    colored_text.insert_colored("Network Printer Exposed\n")

    colored_text.insert_colored("\n[✓] Scan complete!\n", "success")

    # Test buttons
    button_frame = ttk.Frame(root)
    button_frame.pack(pady=10)


    def test_progress():
        progress_bar.start("Scanning network... Please wait")
        root.after(3000, progress_bar.stop)


    ttk.Button(button_frame, text="Test Progress Bar",
               command=test_progress).pack(side=tk.LEFT, padx=5)

    root.mainloop()