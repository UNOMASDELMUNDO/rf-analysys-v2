#!/usr/bin/env python3
import os
import numpy as np
from datetime import datetime, timezone
from scapy.all import *
from collections import defaultdict
from pymongo import MongoClient
from redis import Redis

MONGODB_URL = os.environ.get("MONGODB_URL", "mongodb://localhost:27228")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
ML_ENABLED = os.environ.get("ML_ENABLED", "true").lower() == "true"

class TrafficClassifier:
    def classify(self, pkt):
        if TCP in pkt:
            dport = pkt[TCP].dport
            if dport == 443: return {"type": "https", "confidence": 0.95}
            elif dport == 1883: return {"type": "mqtt", "confidence": 0.90}
            elif dport == 80: return {"type": "http", "confidence": 0.90}
            elif dport == 8123: return {"type": "homeassistant", "confidence": 0.85}
        elif UDP in pkt:
            dport = pkt[UDP].dport
            if dport == 5353: return {"type": "mdns", "confidence": 0.90}
            elif dport == 53: return {"type": "dns", "confidence": 0.90}
            elif dport == 5683: return {"type": "coap", "confidence": 0.85}
        return {"type": "unknown", "confidence": 0.0}

class AdvancedSniffer:
    def __init__(self):
        self.classifier = TrafficClassifier() if ML_ENABLED else None
        self.devices = defaultdict(dict)
        self.packets = []
        self.packet_records = []

    def process_packet(self, pkt):
        if IP not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        port = 0
        proto = "unknown"
        if TCP in pkt:
            proto = "tcp"
            port = pkt[TCP].dport
        elif UDP in pkt:
            proto = "udp"
            port = pkt[UDP].dport
        ml_classification = {}
        if self.classifier:
            ml_classification = self.classifier.classify(pkt)
        record = {
            "src_ip": src,
            "dst_ip": dst,
            "protocol": proto,
            "port": port,
            "ml_classification": ml_classification,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        if Raw in pkt:
            try:
                record["payload_preview"] = pkt[Raw].load[:50].hex()
            except:
                pass
        if src not in self.devices:
            self.devices[src] = {
                "ip": src,
                "mac": pkt[Ether].src if Ether in pkt else "unknown",
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "traffic_types": set()
            }
        self.devices[src]["last_seen"] = datetime.now(timezone.utc).isoformat()
        if ml_classification:
            self.devices[src]["traffic_types"].add(ml_classification.get("type", "unknown"))
        self.packets.append(pkt)
        self.packet_records.append(record)

    def save_to_mongodb(self):
        if not self.packet_records:
            print("[!] No packets to save")
            return
        print(f"\n[*] Saving {len(self.packet_records)} packets to MongoDB...")
        try:
            db = MongoClient(MONGODB_URL)['rf_analyzer_v2']
            db.packets.insert_many(self.packet_records)
            for ip, dev in self.devices.items():
                dev["traffic_types"] = list(dev["traffic_types"])
                db.devices.update_one({"ip": ip}, {"$set": dev}, upsert=True)
            print("[+] Data saved to MongoDB")
        except Exception as e:
            print(f"[!] MongoDB error: {e}")
        try:
            redis = Redis.from_url(REDIS_URL)
            redis.incr("metrics:packets_captured", len(self.packet_records))
            print("[+] Redis metrics updated")
        except Exception as e:
            print(f"[!] Redis error: {e}")

    def run(self, count=500, timeout=120):
        print("="*60)
        print("ADVANCED SNIFFER V2 WITH ML")
        print(f"ML Enabled: {ML_ENABLED}")
        print("="*60)
        print(f"\n[*] Capturing {count} packets (timeout: {timeout}s)...")
        try:
            self.packets = sniff(prn=self.process_packet, count=count, timeout=timeout)
            print(f"[+] Captured {len(self.packets)} packets")
        except Exception as e:
            print(f"[!] Error: {e}")
        self.analyze()
        self.save_to_mongodb()
        print("\n[*] Capture complete!")

    def analyze(self):
        if not self.packet_records:
            print("[!] No packets to analyze")
            return
        print("\n[*] Analyzing traffic...")
        protocols = defaultdict(int)
        ports = defaultdict(int)
        for record in self.packet_records:
            protocols[record["protocol"]] += 1
            if record["port"]:
                ports[record["port"]] += 1
        print(f"\nProtocols: {dict(protocols)}")
        print(f"Top ports: {sorted(ports.items(), key=lambda x: x[1], reverse=True)[:5]}")

if __name__ == "__main__":
    sniffer = AdvancedSniffer()
    sniffer.run()
