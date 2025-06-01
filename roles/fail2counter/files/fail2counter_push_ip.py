#!/usr/bin/env python3
import sys, redis, datetime

IP = sys.argv[1]
r = redis.Redis(host='localhost', port=6379, db=0)
r.rpush("banned_ips", f"{datetime.datetime.utcnow().isoformat()}|{IP}")
