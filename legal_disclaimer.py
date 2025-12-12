import tkinter as tk
from tkinter import messagebox, scrolledtext
import json
import os
import socket
from datetime import datetime


class LegalDisclaimerDialog:

    def __init__(self, parent=None):
        self.parent = parent
        self.accepted = False
        self.consent_log_file = "consent_log.json"

    def show_disclaimer(self):
        dialog = tk.Toplevel(self.parent) if self.parent else tk.Tk()
        dialog.title("IoTective - Legal Notice & User Agreement")
        dialog.iconbitmap('iotective_icon.ico')
        dialog.geometry("700x600")
        dialog.resizable(False, False)

        if self.parent:
            dialog.transient(self.parent)

        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (700 // 2)
        y = (dialog.winfo_screenheight() // 2) - (600 // 2)
        dialog.geometry(f"700x600+{x}+{y}")

        dialog.lift()
        dialog.focus_force()
        if self.parent:
            dialog.grab_set()

        # Header
        header_frame = tk.Frame(dialog, bg="#d32f2f", height=60)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)

        tk.Label(
            header_frame,
            text="⚠️  LEGAL NOTICE - READ CAREFULLY",
            font=("Arial", 16, "bold"),
            bg="#d32f2f",
            fg="white"
        ).pack(pady=15)

        content_frame = tk.Frame(dialog, padx=20, pady=20)
        content_frame.pack(fill=tk.BOTH, expand=True)

        disclaimer_text = """
IoTective - USER AGREEMENT

IMPORTANT LEGAL NOTICE:
This software is designed for authorized security testing and educational purposes only. 
By using this tool, you acknowledge and agree to the following terms:

1. AUTHORIZED USE ONLY
   • You may ONLY scan networks that you own or have explicit written permission to test
   • Unauthorized network scanning may violate federal and state laws including:
     - Computer Fraud and Abuse Act (CFAA) - 18 U.S.C. § 1030
     - Electronic Communications Privacy Act (ECPA)
     - State computer crime laws
   • Violation of these laws can result in criminal prosecution and civil liability

2. USER RESPONSIBILITIES
   • You are solely responsible for your use of this software
   • You must obtain proper authorization before scanning any network
   • You must comply with all applicable local, state, and federal laws
   • You must respect the privacy and property rights of others

3. EDUCATIONAL PURPOSE
   • This tool is intended for cybersecurity education and research
   • Use in controlled environments (home networks, lab environments) only
   • Not intended for unauthorized penetration testing or malicious activities

BY CLICKING "I ACCEPT", YOU ACKNOWLEDGE THAT:
   ✓ You have read and understood this agreement
   ✓ You have authorization to scan the target network
   ✓ You will use this tool responsibly and legally
   ✓ You accept full responsibility for your actions
   ✓ You understand the potential legal consequences of misuse

If you do not agree to these terms, click "I DECLINE" to exit.
        """

        text_widget = scrolledtext.ScrolledText(
            content_frame,
            wrap=tk.WORD,
            width=80,
            height=20,
            font=("Courier", 9),
            bg="#f5f5f5",
            relief=tk.SUNKEN,
            borderwidth=2
        )
        text_widget.insert(1.0, disclaimer_text)
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        confirm_var = tk.BooleanVar(value=False)
        confirm_check = tk.Checkbutton(
            content_frame,
            text="I have read and understood the above legal notice",
            variable=confirm_var,
            font=("Arial", 10),
            wraplength=650
        )
        confirm_check.pack(anchor=tk.W, pady=(5, 10))

        auth_var = tk.BooleanVar(value=False)
        auth_check = tk.Checkbutton(
            content_frame,
            text="I confirm that I have authorization to scan the target network(s)",
            variable=auth_var,
            font=("Arial", 10, "bold"),
            fg="#d32f2f",
            wraplength=650
        )
        auth_check.pack(anchor=tk.W, pady=(0, 15))

        button_frame = tk.Frame(content_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        result = {'accepted': False}

        def on_accept():
            if not confirm_var.get() or not auth_var.get():
                messagebox.showwarning(
                    "Incomplete Acknowledgment",
                    "You must check both boxes to proceed.",
                    parent=dialog
                )
                return

            self.log_consent(accepted=True)
            result['accepted'] = True
            dialog.destroy()

        def on_decline():
            response = messagebox.askyesno(
                "Decline Agreement",
                "Are you sure you want to decline?",
                parent=dialog
            )
            if response:
                self.log_consent(accepted=False)
                result['accepted'] = False
                dialog.destroy()

        tk.Button(
            button_frame,
            text="I ACCEPT - Proceed to Scanner",
            command=on_accept,
            bg="#4caf50",
            fg="white",
            font=("Arial", 11, "bold"),
            width=25,
            height=2
        ).pack(side=tk.LEFT, expand=True, padx=5)

        tk.Button(
            button_frame,
            text="I DECLINE - Exit",
            command=on_decline,
            bg="#f44336",
            fg="white",
            font=("Arial", 11, "bold"),
            width=25,
            height=2
        ).pack(side=tk.LEFT, expand=True, padx=5)

        tk.Label(
            content_frame,
            text="⚠️ Unauthorized network scanning is illegal and may result in prosecution",
            font=("Arial", 9, "italic"),
            fg="#d32f2f",
            wraplength=650
        ).pack(pady=(15, 0))

        dialog.protocol("WM_DELETE_WINDOW", on_decline)
        dialog.wait_window(dialog)

        self.accepted = result['accepted']
        return self.accepted

    def log_consent(self, accepted):
        consent_record = {
            "timestamp": datetime.now().isoformat(),
            "accepted": accepted,
            "hostname": socket.gethostname(),
            "version": "1.0"
        }

        logs = []
        if os.path.exists(self.consent_log_file):
            try:
                with open(self.consent_log_file, 'r') as f:
                    logs = json.load(f)
            except Exception:
                logs = []

        logs.append(consent_record)

        try:
            with open(self.consent_log_file, 'w') as f:
                json.dump(logs, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not log consent: {e}")
