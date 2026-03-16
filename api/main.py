#!/usr/bin/env python3
"""
RF Analyzer V2 - REST API
"""
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from redis import Redis
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel

app = FastAPI(title="RF Analyzer V2 API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database connections
MONGODB_URL = os.environ.get("MONGODB_URL", "mongodb://rf2-mongodb:27228")
REDIS_URL = os.environ.get("REDIS_URL", "redis://rf2-redis:6379")

def get_db():
    client = MongoClient(MONGODB_URL)
    return client['rf_analyzer_v2']

def get_redis():
    return Redis.from_url(REDIS_URL)

# Models
class Device(BaseModel):
    ip: str
    mac: str
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    risk_score: Optional[int] = 0

class Signal(BaseModel):
    frequency: float
    protocol: str
    modulation: Optional[str] = None
    bandwidth: Optional[float] = None
    power_dbm: Optional[float] = None
    snr: Optional[float] = None
    device_category: Optional[str] = None
    ml_classification: Optional[dict] = None
    anomaly_score: Optional[float] = None
    timestamp: datetime

class Alert(BaseModel):
    severity: str  # low, medium, high, critical
    source: str
    description: str
    recommended_action: str
    timestamp: datetime

# Routes
@app.get("/")
def root():
    return {"status": "ok", "version": "2.0.0", "timestamp": datetime.utcnow().isoformat()}

@app.get("/health")
def health():
    try:
        db = get_db()
        db.command("ping")
        redis = get_redis()
        redis.ping()
        return {"status": "healthy", "mongodb": "ok", "redis": "ok"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))

# Devices
@app.get("/api/v2/devices")
def get_devices(limit: int = 100):
    db = get_db()
    devices = list(db.devices.find({}, {"_id": 0}).limit(limit))
    return {"total": len(devices), "devices": devices}

@app.get("/api/v2/devices/{ip}")
def get_device(ip: str):
    db = get_db()
    device = db.devices.find_one({"ip": ip}, {"_id": 0})
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device

@app.post("/api/v2/devices")
def add_device(device: Device):
    db = get_db()
    result = db.devices.insert_one(device.dict())
    return {"id": str(result.inserted_id), "status": "created"}

# Signals
@app.get("/api/v2/signals")
def get_signals(limit: int = 100):
    db = get_db()
    signals = list(db.signals.find({}, {"_id": 0}).limit(limit))
    return {"total": len(signals), "signals": signals}

@app.get("/api/v2/signals/ml-classified")
def get_ml_classified_signals(limit: int = 50):
    db = get_db()
    signals = list(db.signals.find(
        {"ml_classification": {"$exists": True}},
        {"_id": 0}
    ).limit(limit))
    return {"total": len(signals), "signals": signals}

# ML Analysis
@app.get("/api/v2/ml/anomalies")
def get_anomalies(threshold: float = 0.7):
    db = get_db()
    anomalies = list(db.signals.find(
        {"anomaly_score": {"$gte": threshold}},
        {"_id": 0}
    ))
    return {"total": len(anomalies), "anomalies": anomalies}

@app.get("/api/v2/ml/classification/{signal_id}")
def get_classification(signal_id: str):
    db = get_db()
    signal = db.signals.find_one({"signal_id": signal_id}, {"_id": 0})
    if not signal:
        raise HTTPException(status_code=404, detail="Signal not found")
    return signal.get("ml_classification", {})

# Alerts
@app.get("/api/v2/alerts")
def get_alerts(severity: Optional[str] = None, limit: int = 50):
    db = get_db()
    query = {"severity": severity} if severity else {}
    alerts = list(db.alerts.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit))
    return {"total": len(alerts), "alerts": alerts}

@app.post("/api/v2/alerts")
def create_alert(alert: Alert):
    db = get_db()
    result = db.alerts.insert_one(alert.dict())
    
    # Also publish to Redis for real-time notifications
    redis = get_redis()
    redis.publish("alerts", alert.dict())
    
    return {"id": str(result.inserted_id), "status": "created"}

# Statistics
@app.get("/api/v2/stats")
def get_stats():
    db = get_db()
    redis = get_redis()
    
    return {
        "devices": db.devices.count_documents({}),
        "signals": db.signals.count_documents({}),
        "alerts": db.alerts.count_documents({}),
        "ml_classified": db.signals.count_documents({"ml_classification": {"$exists": True}}),
        "anomalies": db.signals.count_documents({"anomaly_score": {"$gte": 0.7}}),
        "redis_connected": redis.ping(),
        "timestamp": datetime.utcnow().isoformat()
    }

# Real-time metrics
@app.get("/api/v2/metrics")
def get_metrics():
    redis = get_redis()
    
    metrics = {
        "packets_captured": redis.get("metrics:packets_captured") or 0,
        "threats_detected": redis.get("metrics:threats_detected") or 0,
        "ml_predictions": redis.get("metrics:ml_predictions") or 0,
        "alerts_sent": redis.get("metrics:alerts_sent") or 0,
    }
    return metrics

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8889)
