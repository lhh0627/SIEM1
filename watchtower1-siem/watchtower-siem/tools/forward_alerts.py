#!/usr/bin/env python3
"""Replay stored Wazuh alerts (alerts.json, one JSON per line) into Watchtower. Safe to re-run: duplicates are skipped by alert id.
Usage: python forward_alerts.py alerts.json [--url http://localhost:8000] [--key KEY]"""
import sys, json, argparse, urllib.request
ap = argparse.ArgumentParser(); ap.add_argument("file"); ap.add_argument("--url", default="http://localhost:8000"); ap.add_argument("--key", default="")
a = ap.parse_args(); batch, sent = [], 0
def flush():
    global batch, sent
    if not batch: return
    urllib.request.urlopen(urllib.request.Request(a.url + "/api/ingest", json.dumps(batch).encode(), {"Content-Type": "application/json", "X-API-Key": a.key}), timeout=30); sent += len(batch); batch = []
for line in open(a.file):
    if line.strip(): batch.append(json.loads(line))
    if len(batch) >= 100: flush()
flush(); print("sent", sent, "alerts")
