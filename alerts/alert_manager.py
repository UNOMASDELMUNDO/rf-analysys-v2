#!/usr/bin/env python3
"""
Alert Manager V2 - Real-time notifications
"""
import os
import json
from datetime import datetime, timezone
from pymongo import MongoClient
from redis import Redis
import requests

MONGODB_URL = os.environ.get("MONGODB_URL", "mongodb://rf2-mongodb:27228")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")

class AlertManager:
    def __init__(self):
        self.db = MongoClient(MONGODB_URL)['rf_analyzer_v2']
        self.redis = Redis.from_url(REDIS_URL)
        self.pubsub = self.redis.pubsub()
    
    def send_telegram(self, message):
        """Send Telegram notification"""
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
            return False
        
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }
        
        try:
            response = requests.post(url, json=data, timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"[!] Telegram error: {e}")
            return False
    
    def send_discord(self, message):
        """Send Discord webhook notification"""
        if not DISCORD_WEBHOOK_URL:
            return False
        
        data = {"content": message}
        
        try:
            response = requests.post(DISCORD_WEBHOOK_URL, json=data, timeout=10)
            return response.status_code == 204
        except Exception as e:
            print(f"[!] Discord error: {e}")
            return False
    
    def notify(self, alert):
        """Send notifications for alert"""
        severity_emoji = {
            "low": "ℹ️",
            "medium": "⚠️",
            "high": "🚨",
            "critical": "🔥"
        }
        
        emoji = severity_emoji.get(alert.get("severity", "medium"), "⚠️")
        
        message = f"""
{emoji} <b>RF Analyzer Alert</b>

<b>Severity:</b> {alert.get("severity", "medium").upper()}
<b>Source:</b> {alert.get("source", "unknown")}
<b>Description:</b> {alert.get("description", "N/A")}
<b>Action:</b> {alert.get("recommended_action", "N/A")}
<b>Time:</b> {alert.get("timestamp", "N/A")}
        """
        
        # Send to all channels
        self.send_telegram(message)
        self.send_discord(message)
        
        # Update counter
        self.redis.incr("metrics:alerts_sent")
        
        return True
    
    def process_alerts(self):
        """Process pending alerts"""
        # Get recent high/critical alerts
        alerts = list(self.db.alerts.find(
            {"notification_sent": {"$ne": True}, "severity": {"$in": ["high", "critical"]}}
        ).limit(10))
        
        for alert in alerts:
            self.notify(alert)
            
            # Mark as sent
            self.db.alerts.update_one(
                {"_id": alert["_id"]},
                {"$set": {"notification_sent": True}}
            )
        
        return len(alerts)
    
    def listen_realtime(self):
        """Listen for real-time alerts via Redis"""
        print("[*] Listening for real-time alerts...")
        self.pubsub.subscribe("alerts")
        
        for message in self.pubsub.listen():
            if message["type"] == "message":
                try:
                    alert = json.loads(message["data"])
                    self.notify(alert)
                except:
                    pass
    
    def run(self):
        """Run alert manager"""
        print("="*60)
        print("ALERT MANAGER V2")
        print(f"Telegram: {'✓' if TELEGRAM_BOT_TOKEN else '✗'}")
        print(f"Discord: {'✓' if DISCORD_WEBHOOK_URL else '✗'}")
        print("="*60)
        
        # Process existing alerts
        while True:
            try:
                sent = self.process_alerts()
                if sent:
                    print(f"[+] Sent {sent} notifications")
                
                # Also listen for real-time
                self.listen_realtime()
                
            except Exception as e:
                print(f"[!] Error: {e}")
            
            import time
            time.sleep(10)


if __name__ == "__main__":
    manager = AlertManager()
    manager.run()
