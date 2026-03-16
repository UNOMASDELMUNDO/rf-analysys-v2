#!/usr/bin/env python3
"""
ML Engine V2 - Signal Classification & Anomaly Detection
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from pymongo import MongoClient
from redis import Redis
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MONGODB_URL = os.environ.get("MONGODB_URL", "mongodb://rf2-mongodb:27228")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")

class MLEngine:
    def __init__(self):
        self.db = MongoClient(MONGODB_URL)['rf_analyzer_v2']
        self.redis = Redis.from_url(REDIS_URL)
        
        # ML Models
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        
        self.init_models()
    
    def init_models(self):
        """Initialize ML models"""
        print("[*] Initializing ML models...")
        
        # Anomaly detection (Isolation Forest)
        self.anomaly_detector = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        
        # Train with synthetic data initially
        self.train_anomaly_detector()
        
        print("[+] ML models ready")
    
    def train_anomaly_detector(self):
        """Train anomaly detector with existing data"""
        # Get historical data
        signals = list(self.db.signals.find({}, {
            "frequency": 1,
            "power_dbm": 1,
            "bandwidth": 1,
            "snr": 1
        }).limit(1000))
        
        if len(signals) < 10:
            print("[!] Not enough data for training, using synthetic data")
            # Use synthetic normal data
            X = np.random.randn(100, 4)
            X[:, 0] = X[:, 0] * 100 + 900  # Frequency
            X[:, 1] = X[:, 1] * 20 - 50    # Power
            X[:, 2] = X[:, 2] * 200 + 200 # Bandwidth
            X[:, 3] = X[:, 3] * 10 + 10    # SNR
        else:
            # Use real data
            X = []
            for s in signals:
                X.append([
                    s.get("frequency", 0),
                    s.get("power_dbm", -50),
                    s.get("bandwidth", 0),
                    s.get("snr", 0)
                ])
            X = np.array(X)
        
        # Fit scaler
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        # Fit anomaly detector
        self.anomaly_detector.fit(X_scaled)
        
        print(f"[+] Trained with {len(X)} samples")
    
    def extract_features(self, signal):
        """Extract features from signal"""
        features = [
            signal.get("frequency", 0),
            signal.get("power_dbm", -50),
            signal.get("bandwidth", 0),
            signal.get("snr", 0)
        ]
        return np.array(features).reshape(1, -1)
    
    def classify_signal(self, signal):
        """Classify signal type using rules + ML"""
        features = self.extract_features(signal)
        
        # Rule-based classification
        protocol = "unknown"
        modulation = "unknown"
        category = "general"
        
        freq = signal.get("frequency", 0)
        
        if 2400 <= freq <= 2480:
            if "BLE" in signal.get("protocol", "") or "bluetooth" in signal.get("protocol", "").lower():
                protocol = "BLE"
                modulation = "GFSK"
                category = "bluetooth"
            elif "zigbee" in signal.get("protocol", "").lower():
                protocol = "Zigbee"
                modulation = "O-QPSK"
                category = "iot"
        elif 2400 <= freq <= 2500:
            protocol = "WiFi"
            modulation = "OFDM"
            category = "wifi"
        elif 5150 <= freq <= 5850:
            protocol = "WiFi_5GHz"
            modulation = "OFDM"
            category = "wifi"
        elif 433.0 <= freq <= 434.0:
            protocol = "ISM_433MHz"
            modulation = "ASK/OOK"
            category = "iot"
        elif 868.0 <= freq <= 870.0:
            protocol = "ISM_868MHz"
            modulation = "FSK"
            category = "iot"
        elif 902 <= freq <= 928:
            protocol = "ISM_915MHz"
            modulation = "FSK"
            category = "iot"
        
        # Anomaly detection
        features_scaled = self.scaler.transform(features)
        anomaly_score = float(self.anomaly_detector.decision_function(features_scaled)[0])
        is_anomaly = bool(self.anomaly_detector.predict(features_scaled)[0] == -1)
        
        # Risk assessment
        risk_score = 0
        if is_anomaly:
            risk_score += 5
        if protocol == "unknown":
            risk_score += 3
        if category == "iot":
            risk_score += 2
        
        risk_score = min(10, max(0, risk_score))
        
        return {
            "protocol": protocol,
            "modulation": modulation,
            "category": category,
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "risk_score": risk_score,
            "ml_version": "2.0",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    def process_signals(self):
        """Process all unclassified signals"""
        print("\n[*] Processing signals with ML...")
        
        processed = 0
        
        # Process packets collection
        for packet in self.db.packets.find({"ml_classification": {}}).limit(500):
            classification = self.classify_signal(packet)
            
            self.db.packets.update_one(
                {"_id": packet["_id"]},
                {"$set": {"ml_classification": classification}}
            )
            
            # Create alert for high risk
            if classification["risk_score"] >= 7:
                alert = {
                    "severity": "high",
                    "source": f"ml_engine",
                    "description": f"Anomalous traffic detected: {classification['category']}",
                    "recommended_action": "Investigate device behavior",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "related_ip": packet.get("src_ip", "unknown")
                }
                self.db.alerts.insert_one(alert)
                self.redis.incr("metrics:threats_detected")
            
            processed += 1
        
        self.redis.incr("metrics:ml_predictions", processed)
        
        print(f"[+] Processed {processed} signals")
        return processed
    
    def run_continuous(self):
        """Run ML engine continuously"""
        print("="*60)
        print("ML ENGINE V2 - RUNNING")
        print("="*60)
        
        while True:
            try:
                processed = self.process_signals()
                print(f"[*] Waiting for new data...")
                import time
                time.sleep(30)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] Error: {e}")
                import time
                time.sleep(5)


if __name__ == "__main__":
    engine = MLEngine()
    engine.run_continuous()
