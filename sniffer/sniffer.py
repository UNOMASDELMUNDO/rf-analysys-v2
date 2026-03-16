#!/usr/bin/env python3
"""
Network Sniffer V2 with ML Classification
"""
import os
import json
import joblib
import numpy as np
from datetime import datetime, timezone
from scapy.all import *
from collections import defaultdict
from pymongo import MongoClient
from redis import Redis

# Configuration
MONGODB_URL = os.environ.get("MONGODB_URL", "mongodb://rf2-mongodb:27228")
REDIS_URL = os.environ.get("REDIS_URL", "redis://rf2-redis:6379")
ML_ENABLED = os.environ.get("ML_ENABLED", "true").lower() == "true"

# ML Model for traffic classification
class TrafficClassifier:
    def __init__(self):
        self.model = None
        self.load_model()
    
    def load_model(self):
        """Load pre-trained model or create dummy"""
        model_path = "/app/model_traffic.joblib"
        if os.path.exists(model_path):
            self.model = joblib.load(model_path)
            print("[+] ML Model loaded")
        else:
            print("[!] No ML model found, using rule-based classification")
            self.model = None
    
    def extract_features(self, pkt):
        """Extract features from packet for ML"""
        features = []
        
        # Basic features
        features.append(1 if IP in pkt else 0)  # Has IP
        features.append(1 if TCP in pkt else 0)  # TCP
        features.append(1 if UDP in pkt else 0)  # UDP
        
        # Port features
        if TCP in pkt:
            features.append(pkt[TCP].sport)
            features.append(pkt[TCP].dport)
        else:
            features.extend([0, 0])
        
        if UDP in pkt:
            features.append(pkt[UDP].sport)
            features.append(pkt[UDP].dport)
        else:
            features.extend([0, 0])
        
        # Payload size
        if Raw in pkt:
            features.append(len(pkt[Raw].load))
        else:
            features.append(0)
        
        return np.array(features).reshape(1, -1)
    
    def classify(self, pkt):
        """Classify packet traffic type"""
        if not self.model:
            # Rule-based fallback
            if TCP in pkt:
                if pkt[TCP].dport == 443:
                    return {"type": "https", "confidence": 0.95}
                elif pkt[TCP].dport == 1883:
                    return {"type": "mqtt", "confidence": 0.90}
                elif pkt[TCP].dport == 80:
                    return {"type": "http", "confidence": 0.90}
                elif pkt[TCP].dport == 8123:
                    return {"type": "homeassistant", "confidence": 0.85}
            elif UDP in pkt:
                if pkt[UDP].dport == 5353:
                    return {"type": "mdns", "confidence": 0.90}
                elif pkt[UDP].dport == 53:
                    return {"type": "dns", "confidence": 0.90}
                elif pkt[UDP].dport == 5683:
                    return {"type": "coap", "confidence": 0.85}
            
            return {"type": "unknown", "confidence": 0.0}
        
        # ML prediction
        features = self.extract_features(pkt)
        prediction = self.model.predict(features)[0]
        
        return {"type": prediction, "confidence": 0.85}


class AdvancedSniffer:
    def __init__(self):
        self.db = MongoClient(MONGODB_URL)['rf_analyzer_v2']
        self.redis = Redis.from_url(REDIS_URL)
        self.classifier = TrafficClassifier() if ML_ENABLED else None
        self.devices = defaultdict(dict)
        self.packets = []
    
    def process_packet(self, pkt):
        """Process and analyze packet"""
        if IP not in pkt:
            return
        
        src = pkt[IP].src
        dst = pkt[IP].dst
        
        # Get ports
        port = 0
        proto = "unknown"
        
        if TCP in pkt:
            proto = "tcp"
            port = pkt[TCP].dport
        elif UDP in pkt:
            proto = "udp"
            port = pkt[UDP].dport
        
        # ML Classification
        ml_classification = {}
        if self.classifier:
            ml_classification = self.classifier.classify(pkt)
            self.redis.incr("metrics:ml_predictions")
        
        # Build record
        record = {
            "src_ip": src,
            "dst_ip": dst,
            "protocol": proto,
            "port": port,
            "ml_classification": ml_classification,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Add payload preview (hex)
        if Raw in pkt:
            record["payload_preview"] = pkt[Raw].load[:50].hex()
        
        # Store device info
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
        
        self.packets.append(record)
        
        # Real-time Redis counter
        self.redis.incr("metrics:packets_captured")
    
    def save_to_mongodb(self):
        """Save captured data to MongoDB"""
        print(f"\n[*] Saving {len(self.packets)} packets to MongoDB...")
        
        # Save packets
        if self.packets:
            self.db.packets.insert_many(self.packets)
        
        # Save devices
        for ip, dev in self.devices.items():
            dev["traffic_types"] = list(dev["traffic_types"])
            self.db.devices.update_one(
                {"ip": ip},
                {"$set": dev},
                upsert=True
            )
        
        print("[+] Data saved to MongoDB")
    
    def run(self, count=500, timeout=120):
        """Run sniffer"""
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
        
        # Analyze
        self.analyze()
        
        # Save
        self.save_to_mongodb()
        
        print("\n[*] Capture complete!")
    
    def analyze(self):
        """Analyze captured traffic"""
        print("\n[*] Analyzing traffic...")
        
        protocols = defaultdict(int)
        ports = defaultdict(int)
        
        for pkt in self.packets:
            protocols[pkt["protocol"]] += 1
            if pkt["port"]:
                ports[pkt["port"]] += 1
        
        print(f"\nProtocols: {dict(protocols)}")
        print(f"Top ports: {sorted(ports.items(), key=lambda x: x[1], reverse=True)[:5]}")


if __name__ == "__main__":
    sniffer = AdvancedSniffer()
    sniffer.run()
