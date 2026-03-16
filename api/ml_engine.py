#!/usr/bin/env python3
"""
ML Engine for RF Analyzer V2
- Device classification
- Anomaly detection
- Traffic pattern analysis
- Threat detection
"""
import os
import json
import numpy as np
from datetime import datetime, timedelta
from collections import Counter
from pymongo import MongoClient

MONGODB_URL = os.environ.get("MONGODB_URL", "mongodb://mongodb:27017")

# OUI Database - primeros 3 bytes MAC
OUI_VENDORS = {
    '00:D8:61': 'Dell Inc.',
    '00:1A:2B': 'Cisco Systems',
    '00:50:56': 'VMware Inc.',
    '08:00:27': 'VirtualBox',
    '1C:F4:3F': 'Google LLC',
    '26:51:6C': 'Unknown',
    'B8:27:EB': 'Raspberry Pi Foundation',
    'DC:A6:32': 'Raspberry Pi Foundation',
    'E4:5F:01': 'Raspberry Pi Trading Ltd',
    '00:0C:29': 'VMware Inc.',
    '00:1C:42': 'Parallels Inc.',
    'AC:DE:48': 'Private',
    'F0:18:98': 'Apple Inc.',
    '3C:06:30': 'Apple Inc.',
    'A4:83:E7': 'Apple Inc.',
    '00:25:00': 'Apple Inc.',
    '00:1F:F3': 'Apple Inc.',
    'DC:2B:2A': 'Apple Inc.',
    '28:6A:B8': 'Xiaomi',
    '34:80:B3': 'Xiaomi',
    '64:B4:73': 'Samsung',
    '8C:F5:A3': 'Samsung',
    '00:1D:F6': 'Hewlett Packard',
    '00:21:5A': 'Hewlett Packard',
    '00:17:42': 'Cisco-Linksys',
    'C0:C1:C0': 'D-Link',
    '1C:AF:F7': 'D-Link',
    '00:1E:58': 'D-Link',
    '00:24:01': 'NETGEAR',
    'C4:04:15': 'NETGEAR',
    'C0:3F:0E': 'NETGEAR',
    'E0:46:9A': 'NETGEAR',
    'E0:91:F5': 'TP-Link',
    '50:C7:BF': 'TP-Link',
    '54:C8:0F': 'TP-Link',
    'A4:2B:B0': 'TP-Link',
    'EC:08:6B': 'ESP32',
    '30:AE:A4': 'ESP32',
    '24:6F:28': 'ESP32',
}

# Known ports and protocols
PORT_SERVICES = {
    22: 'SSH',
    22: 'SSH',
    80: 'HTTP',
    443: 'HTTPS',
    53: 'DNS',
    67: 'DHCP',
    68: 'DHCP',
    123: 'NTP',
    161: 'SNMP',
    1883: 'MQTT',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    6379: 'Redis',
    27017: 'MongoDB',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    8123: 'Home Assistant',
    5353: 'mDNS',
    5683: 'CoAP',
    8883: 'MQTT-TLS',
    8884: 'MQTT-TLS',
    502: 'Modbus',
    102: 'S7comm',
}

# Device signatures by ports/patterns
DEVICE_SIGNATURES = {
    'router': {'ports': [80, 443, 8080], 'patterns': ['192.168.1.1', 'gateway']},
    'iot_camera': {'ports': [554, 8554, 8080], 'patterns': ['rtsp']},
    'smart_tv': {'ports': [8001, 8008, 9000], 'patterns': []},
    'smart_speaker': {'ports': [443, 8080], 'patterns': ['alexa', 'google home']},
    'home_assistant': {'ports': [8123, 8123], 'patterns': []},
    'esp32': {'ports': [80, 3232], 'patterns': []},
    'raspberry_pi': {'ports': [22, 80, 443], 'patterns': []},
    'printer': {'ports': [80, 631, 9100], 'patterns': []},
    'nas': {'ports': [5000, 5001, 445], 'patterns': []},
    'game_console': {'ports': [3478, 3479, 3480], 'patterns': []},
}

class MLEngine:
    def __init__(self):
        self.client = MongoClient(MONGODB_URL)
        self.db = self.client['rf_analyzer_v2']
        
    def get_vendor(self, mac):
        if not mac or mac == 'unknown':
            return 'Unknown'
        prefix = mac.replace(':', '').upper()[:6]
        return OUI_VENDORS.get(prefix, 'Unknown')
    
    def classify_device(self, device):
        """Clasifica dispositivo basado en MAC, IP, puertos y tráfico"""
        ip = device.get('ip', '')
        mac = device.get('mac', '')
        traffic_types = device.get('traffic_types', [])
        
        # Por MAC
        vendor = self.get_vendor(mac)
        
        # Por IP
        device_type = 'Unknown'
        if ip.startswith('192.168.1.1') or ip.endswith('.1'):
            device_type = 'Router/Gateway'
        elif ip.startswith('192.168.1.'):
            device_type = 'Local Device'
            
        # Por tráfico
        if traffic_types:
            if 'mdns' in traffic_types:
                device_type = 'Apple Device'
            elif 'homeassistant' in traffic_types:
                device_type = 'Smart Home Hub'
            elif 'mqtt' in traffic_types:
                device_type = 'IoT Device'
            elif 'http' in traffic_types or 'https' in traffic_types:
                device_type = 'Web Device'
        
        # Por vendor
        if 'Raspberry' in vendor:
            device_type = 'Single Board Computer'
        elif 'Dell' in vendor:
            device_type = 'Desktop/Laptop'
        elif 'VMware' in vendor or 'VirtualBox' in vendor:
            device_type = 'Virtual Machine'
        elif 'Apple' in vendor:
            device_type = 'Apple Device'
        elif 'ESP' in vendor:
            device_type = 'IoT Microcontroller'
            
        return {
            'vendor': vendor,
            'device_type': device_type,
            'classification_method': 'ml_rules'
        }
    
    def detect_anomalies(self):
        """Detecta anomalías en el tráfico"""
        anomalies = []
        
        # Puertos inusuales
        unusual_ports = [4444, 5555, 6666, 7777, 8888, 9999, 31337]
        
        # Dispositivos sin tráfico reciente
        cutoff = datetime.now() - timedelta(minutes=30)
        old_devices = list(self.db.devices.find({
            'last_seen': {'$lt': cutoff.isoformat()}
        }))
        
        for dev in old_devices:
            anomalies.append({
                'type': 'inactive_device',
                'device': dev.get('ip'),
                'message': f"Device {dev.get('ip')} inactive for > 30 min",
                'severity': 'low'
            })
        
        # Por ahora retornamos basic
        return anomalies[:10]
    
    def analyze_traffic_patterns(self):
        """Analiza patrones de tráfico"""
        signals = list(self.db.signals.find().limit(1000))
        
        if not signals:
            return {'status': 'no_data'}
        
        # Protocol distribution
        protocols = Counter(s.get('protocol') for s in signals)
        
        # Top ports
        ports = Counter(s.get('port') for s in signals if s.get('port'))
        
        # Most common destinations
        dst_ips = Counter(s.get('dst_ip') for s in signals)
        
        return {
            'total_packets': len(signals),
            'protocols': dict(protocols.most_common(5)),
            'top_ports': dict(ports.most_common(10)),
            'top_destinations': dict(dst_ips.most_common(10))
        }
    
    def run_ml_classification(self):
        """Ejecuta clasificación ML en todos los dispositivos"""
        devices = list(self.db.devices.find())
        
        classified = 0
        for device in devices:
            classification = self.classify_device(device)
            self.db.devices.update_one(
                {'ip': device['ip']},
                {'$set': {
                    'vendor': classification['vendor'],
                    'device_type': classification['device_type'],
                    'ml_classified': True,
                    'classification_method': classification['classification_method']
                }}
            )
            classified += 1
        
        return {'classified': classified, 'status': 'complete'}

if __name__ == '__main__':
    print("="*60)
    print("ML ENGINE V2")
    print("="*60)
    
    ml = MLEngine()
    
    # Run classification
    print("\n[*] Classifying devices...")
    result = ml.run_ml_classification()
    print(f"[+] Classified {result['classified']} devices")
    
    # Analyze patterns
    print("\n[*] Analyzing traffic patterns...")
    patterns = ml.analyze_traffic_patterns()
    print(f"[+] Patterns: {patterns}")
    
    # Detect anomalies
    print("\n[*] Detecting anomalies...")
    anomalies = ml.detect_anomalies()
    print(f"[+] Found {len(anomalies)} anomalies")
    
    print("\n[+] ML Analysis complete!")
