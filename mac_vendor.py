import requests
import json
import os
import time
from typing import Optional

class MACVendorLookup:
    def __init__(self):
        self.oui_database = {}
        self.cache_file = "oui_cache.json"
        self.api_call_count = 0
        self.load_cache()

    def load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    self.oui_database = json.load(f)
                print(f"[*] Loaded {len(self.oui_database)} OUI entries from cache")
            except Exception as e:
                print(f"[!] Failed to load OUI cache: {e}")
                self.oui_database = {}

    def save_cache(self):
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.oui_database, f, indent=2)
        except Exception as e:
            print(f"[!] Failed to save OUI cache: {e}")

    def lookup_vendor_online(self, mac_address: str) -> Optional[str]:
        try:
            mac_clean = mac_address.replace(':', '').replace('-', '').upper()
            if len(mac_clean) < 6:
                return None

            oui = mac_clean[:6]
            oui_formatted = f"{oui[:2]}:{oui[2:4]}:{oui[4:6]}"

            if oui_formatted in self.oui_database:
                return self.oui_database[oui_formatted]

            url = f"https://api.macvendors.com/{mac_address}"
            response = requests.get(url, timeout=3)
            self.api_call_count += 1

            if response.status_code == 200:
                vendor = response.text.strip()
                self.oui_database[oui_formatted] = vendor
                self.save_cache()
                return vendor
            elif response.status_code == 404:
                self.oui_database[oui_formatted] = "Unknown Vendor"
                self.save_cache()
                return "Unknown Vendor"

        except Exception:
            return None

    def get_vendor(self, mac_address: str) -> str:
        if not mac_address or len(mac_address) < 8:
            return "Invalid MAC"

        vendor = self.lookup_vendor_online(mac_address)
        if vendor:
            time.sleep(0.5)  # Rate limit
            return vendor

        return "Unknown Vendor"

    def identify_device_type(self, vendor: str) -> str:
        if not vendor or vendor == "Unknown Vendor":
            return "Unknown Device Type"

        vendor_lower = vendor.lower()

        iot_patterns = {
            'raspberry pi': 'IoT Controller/Computer',
            'amazon': 'Smart Speaker/IoT Device',
            'google': 'Smart Speaker/Chromecast',
            'nest': 'Smart Thermostat/Camera',
            'ring': 'Smart Doorbell/Security Camera',
            'philips': 'Smart Lighting/Hue',
            'tp-link': 'Smart Plug/Router/Camera',
            'netgear': 'Router/Network Device',
            'cisco': 'Network Equipment',
            'apple': 'Computer/Mobile Device',
            'samsung': 'Mobile Device/Smart TV',
        }

        for pattern, device_type in iot_patterns.items():
            if pattern in vendor_lower:
                return device_type

        return "Unknown Device Type"

    def get_device_info(self, mac_address: str) -> dict:
        """Get complete device information"""
        vendor = self.get_vendor(mac_address)
        device_type = self.identify_device_type(vendor)

        return {
            'vendor': vendor,
            'device_type': device_type
        }
