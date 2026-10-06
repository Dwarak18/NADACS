import argparse
import hashlib
import ipaddress
import json
import os
import random
import time
from datetime import datetime, timezone

import requests


DETECTION_ENGINE_URL = os.getenv("DETECTION_ENGINE_URL", "http://localhost:8000")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def synthetic_flow(agent_id, segment, attack=False):
    src_ip = f"10.0.{random.randint(0, 3)}.{random.randint(2, 250)}"
    dst_ip = f"10.0.{random.randint(0, 3)}.{random.randint(2, 250)}"
    if attack:
        dst_port = random.choice([22, 23, 80, 443, 445, 3389, random.randint(1024, 65535)])
        packets = random.randint(1, 7)
        duration_ms = random.randint(20, 250)
        byte_count = random.randint(60, 900)
        flags = ["SYN"]
    else:
        dst_port = random.choice([53, 80, 123, 443, 5432, 8080])
        packets = random.randint(8, 180)
        duration_ms = random.randint(150, 6000)
        byte_count = packets * random.randint(80, 1500)
        flags = ["SYN", "ACK"] if dst_port in [80, 443, 8080] else []

    flow = {
        "agent_id": agent_id,
        "segment": segment,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(20000, 65000),
        "dst_port": dst_port,
        "protocol": "TCP",
        "bytes": byte_count,
        "packets": packets,
        "duration_ms": duration_ms,
        "start_time": utc_now(),
        "end_time": utc_now(),
        "tcp_flags": flags,
        "metadata": {
            "encrypted": dst_port == 443,
            "private_src": ipaddress.ip_address(src_ip).is_private,
        },
    }
    flow["flow_id"] = hashlib.sha256(json.dumps(flow, sort_keys=True).encode()).hexdigest()
    return flow


def send_flow(flow):
    response = requests.post(f"{DETECTION_ENGINE_URL}/flows", json=flow, timeout=5)
    response.raise_for_status()
    return response.json()


def run_synthetic(count, interval, attack_ratio, agent_id, segment):
    for _ in range(count):
        flow = synthetic_flow(agent_id, segment, attack=random.random() < attack_ratio)
        result = send_flow(flow)
        print(json.dumps({"submitted": flow["flow_id"], "detection": result}, indent=2))
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="NADACS capture agent")
    parser.add_argument("--mode", choices=["synthetic"], default="synthetic")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--interval", type=float, default=0.2)
    parser.add_argument("--attack-ratio", type=float, default=0.25)
    parser.add_argument("--agent-id", default=os.getenv("AGENT_ID", "seg-a-agent-01"))
    parser.add_argument("--segment", default=os.getenv("SEGMENT", "lab-segment-a"))
    args = parser.parse_args()

    run_synthetic(args.count, args.interval, args.attack_ratio, args.agent_id, args.segment)


if __name__ == "__main__":
    main()

