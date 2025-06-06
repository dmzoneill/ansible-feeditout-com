#!/usr/bin/env python3
import os
import json
import logging
import redis
from flask import Flask, request

# === Logging ===
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')

# === Redis config ===
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_PASSWORD = os.environ.get("REDIS_AUTH", None)
REDIS_LIST = os.environ.get("REDIS_LIST", "prometheus_queue")

# === Initialize Redis ===
try:
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD)
    r.ping()
    logging.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}, list '{REDIS_LIST}'")
except redis.RedisError as e:
    logging.error(f"Redis connection failed: {e}")
    exit(1)

# === Initialize Flask ===
app = Flask(__name__)

@app.route("/webhook", methods=["POST"])
def webhook():
    try:
        alerts = request.json.get("alerts", [])
        logging.info(f"Received {len(alerts)} alerts")
        for alert in alerts:
            alert_json = json.dumps(alert)
            r.rpush(REDIS_LIST, alert_json)
            logging.info(f"Queued alert to Redis list: {alert_json}")
        return "", 204
    except Exception as e:
        logging.error(f"Failed to process webhook: {e}")
        return "Error", 500

if __name__ == "__main__":
    logging.info("Starting Prometheus webhook listener on port 5001")
    app.run(host="0.0.0.0", port=5001)
