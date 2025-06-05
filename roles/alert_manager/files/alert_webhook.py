#!/usr/bin/env python3
import os
import json
import redis
from flask import Flask, request

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_PASSWORD = os.environ.get("REDIS_AUTH", None)
REDIS_CHANNEL = os.environ.get("REDIS_CHANNEL", "prometheus")

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD)
app = Flask(__name__)

@app.route("/webhook", methods=["POST"])
def webhook():
    alerts = request.json.get("alerts", [])
    for alert in alerts:
        r.publish(REDIS_CHANNEL, json.dumps(alert))
    return "", 204

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
