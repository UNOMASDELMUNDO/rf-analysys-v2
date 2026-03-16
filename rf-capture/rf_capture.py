#!/usr/bin/env python3
"""
RF Capture - RTL-SDR/HackRF Signal Capture
"""
import os
import json
from datetime import datetime, timezone

MONGODB_URL = os.environ.get("MONGODB_URL", "mongodb://rf2-mongodb:27228")

class RFCapture:
    def __init__(self):
        self.db = None
        self.connect_db()
    
    def connect_db(self):
        try:
            from pymongo import MongoClient
            self.db = MongoClient(MONGODB_URL)['rf_analyzer_v2']
            print("[+] Connected to MongoDB")
        except Exception as e:
            print(f"[!] MongoDB error: {e}")
    
    def scan_frequency(self, freq_mhz, sample_rate=2.4e6, gain=40):
        """Scan a specific frequency"""
        # Note: Requires rtlsdr or hackrf hardware
        # This is a placeholder - actual implementation depends on hardware
        return {
            "frequency": freq_mhz * 1e6,
            "sample_rate": sample_rate,
            "gain": gain,
            "hardware": "rtl-sdr" if os.path.exists("/dev/bus/usb") else "simulated",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    def save_signal(self, signal):
        """Save captured signal to MongoDB"""
        if self.db:
            self.db.signals.insert_one(signal)
            print(f"[+] Saved signal: {signal.get('frequency', 'unknown')} Hz")
    
    def run_demo(self):
        """Run demo with simulated signals"""
        print("="*60)
        print("RF CAPTURE V2 - DEMO MODE")
        print("="*60)
        
        # Simulated frequency scan
        frequencies = [
            433.92,   # ISM 433MHz
            868.0,    # ISM 868MHz
            915.0,    # ISM 915MHz
            2400.0,   # WiFi/BLE
            2440.0,   # BLE
            2480.0,   # BLE
            5150.0,   # WiFi 5GHz
            5500.0,   # WiFi 5GHz
            5800.0,   # WiFi 5GHz
        ]
        
        for freq in frequencies:
            signal = self.scan_frequency(freq)
            signal["protocol"] = self.detect_protocol(freq)
            signal["power_dbm"] = -50 + (hash(str(freq)) % 30)
            signal["bandwidth"] = 200e3 + (hash(str(freq)) % 500) * 1e3
            signal["snr"] = 10 + (hash(str(freq)) % 20)
            self.save_signal(signal)
        
        print(f"\n[+] Captured {len(frequencies)} signals")
    
    def detect_protocol(self, freq):
        """Detect protocol based on frequency"""
        if 2400 <= freq <= 2480:
            return "BLE/WiFi"
        elif 5150 <= freq <= 5850:
            return "WiFi_5GHz"
        elif 433.0 <= freq <= 434.0:
            return "ISM_433MHz"
        elif 868.0 <= freq <= 870.0:
            return "ISM_868MHz"
        elif 902 <= freq <= 928:
            return "ISM_915MHz"
        return "Unknown"

if __name__ == "__main__":
    capture = RFCapture()
    capture.run_demo()
