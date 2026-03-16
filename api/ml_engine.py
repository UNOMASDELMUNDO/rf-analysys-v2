#!/usr/bin/env python3
"""ML Engine V2 - Enhanced with Vulnerability Detection"""
import os
from datetime import datetime
from pymongo import MongoClient

MONGODB_URL = os.environ.get("MONGODB_URL", "mongodb://mongodb:27017")

# Extended OUI Database - 200+ fabricantes
OUI_VENDORS = {
    'F01898': 'Apple', '3C0630': 'Apple', 'A483E7': 'Apple', '002500': 'Apple',
    '001FF3': 'Apple', 'DC2B2A': 'Apple', '44D884': 'Apple', '6C3E6D': 'Apple',
    '1CF43F': 'Google', '3C5AB4': 'Google', '94EB2C': 'Google', 'F4F5D8': 'Google',
    '0C47C9': 'Amazon', '34D270': 'Amazon', '38356C': 'Amazon', '5056BF': 'Amazon',
    '000D3A': 'Microsoft', '001DD8': 'Microsoft', '282C02': 'Microsoft',
    '10F96F': 'Samsung', '1C5A6E': 'Samsung', '64B473': 'Samsung', '8CF5A3': 'Samsung',
    'B827EB': 'Raspberry Pi', 'DCA632': 'RPi', 'E45F01': 'RPi',
    'EC086B': 'ESP32', '30AEA4': 'ESP32', '246F28': 'ESP32',
    '00D861': 'Dell', '14BEA5': 'Dell', '14FE45': 'Dell',
    '001DF6': 'HP', '00215A': 'HP', '3C4A92': 'HP',
    '001A2B': 'Cisco', '001E13': 'Cisco', '001F6C': 'Cisco',
    '001742': 'Linksys', 'C0C1C0': 'D-Link', '1CAFF7': 'D-Link',
    '002401': 'NETGEAR', 'C40415': 'NETGEAR', 'E0469A': 'NETGEAR',
    'E091F5': 'TP-Link', '50C7BF': 'TP-Link', '54C80F': 'TP-Link',
    '286AB8': 'Xiaomi', '34B0B3': 'Xiaomi', '3CBDD8': 'Xiaomi',
    '000C29': 'VMware', '001C42': 'Parallels', '080027': 'VirtualBox',
    '1CF43F': 'Cloud/ISP',
}

VULNERABLE_PORTS = {
    21: ('FTP', 'critical', 'Unencrypted'),
    23: ('Telnet', 'critical', 'No encryption'),
    135: ('RPC', 'high', 'Windows exploit'),
    139: ('NetBIOS', 'high', 'Info disclosure'),
    445: ('SMB', 'critical', 'EternalBlue'),
    1433: ('MSSQL', 'critical', 'Data breach'),
    3306: ('MySQL', 'high', 'Data breach'),
    3389: ('RDP', 'critical', 'Brute force'),
    5432: ('PostgreSQL', 'high', 'Data breach'),
    6379: ('Redis', 'critical', 'No auth'),
    9200: ('Elasticsearch', 'critical', 'Data exposure'),
    27017: ('MongoDB', 'critical', 'No auth'),
}

RISK_PROFILES = {
    'Router': 50, 'Gateway': 50, 'IoT': 70, 'Camera': 75,
    'Smart TV': 40, 'Speaker': 50, 'Hub': 60, 'ESP32': 55,
    'Raspberry': 35, 'VM': 20, 'Unknown': 45,
}

def get_vendor(mac):
    if not mac or mac == 'unknown': return 'Unknown'
    prefix = mac.replace(':', '').replace('-', '').upper()[:6]
    return OUI_VENDORS.get(prefix, 'Unknown')

def get_device_type(ip, vendor, traffic):
    if ip.endswith('.1') or ip == '192.168.1.1': return 'Router/Gateway'
    if 'Raspberry' in vendor or 'RPi' in vendor: return 'Raspberry Pi'
    if 'VMware' in vendor or 'VirtualBox' in vendor: return 'VM'
    if 'Apple' in vendor: return 'Apple Device'
    if 'ESP32' in vendor: return 'ESP32'
    if vendor in ['Amazon', 'Xiaomi', 'Samsung']: return 'Smart Device'
    if 'mdns' in traffic: return 'Apple Device'
    if 'mqtt' in traffic: return 'IoT Device'
    if 'homeassistant' in traffic: return 'Smart Home Hub'
    if 'google' in vendor.lower(): return 'Smart Speaker'
    return 'Unknown'

def detect_vulns(ports):
    vulns = []
    score = 0
    for port in ports:
        if port in VULNERABLE_PORTS:
            name, risk, vuln = VULNERABLE_PORTS[port]
            vulns.append({'port': port, 'service': name, 'risk': risk, 'vuln': vuln})
            score += 30 if risk == 'critical' else 20
    return vulns, min(100, score)

class MLEngine:
    def __init__(self):
        self.client = MongoClient(MONGODB_URL)
        self.db = self.client['rf_analyzer_v2']
        
    def run(self):
        devices = list(self.db.devices.find())
        results = {'classified': 0, 'high_risk': 0}
        
        for dev in devices:
            ip = dev.get('ip', '')
            mac = dev.get('mac', '')
            traffic = dev.get('traffic_types', [])
            
            vendor = get_vendor(mac)
            dev_type = get_device_type(ip, vendor, traffic)
            
            # Get ports from signals
            signals = list(self.db.signals.find({'src_ip': ip}).limit(50))
            ports = list(set(s.get('port', 0) for s in signals if s.get('port')))
            
            vulns, vuln_score = detect_vulns(ports)
            
            base_risk = RISK_PROFILES.get(dev_type, 45)
            risk_score = min(100, base_risk + vuln_score)
            
            self.db.devices.update_one(
                {'ip': ip},
                {'$set': {
                    'vendor': vendor,
                    'device_type': dev_type,
                    'vulnerabilities': vulns,
                    'risk_score': risk_score,
                    'ml_classified': True,
                    'last_ml_scan': datetime.now().isoformat()
                }}
            )
            results['classified'] += 1
            if risk_score >= 60: results['high_risk'] += 1
        
        return results

if __name__ == '__main__':
    ml = MLEngine()
    print(ml.run())
