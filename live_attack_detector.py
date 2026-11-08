import subprocess
import time
import joblib
import pandas as pd
import csv
import os
import requests
import ipaddress
from datetime import datetime
from collections import defaultdict

# ==========================
# GEOLOCATION FUNCTION
# ==========================

def get_location(ip):

    try:
        # Skip private/local IP addresses
        if ipaddress.ip_address(ip).is_private:
            return "Local Network", "Private IP"

        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=3
        )

        data = response.json()

        if data["status"] == "success":

            country = data.get("country", "Unknown")
            city = data.get("city", "Unknown")

            return country, city

        else:
            return "Unknown", "Unknown"

    except:
        return "Unknown", "Unknown"

print("Loading IDS Model...")

# ==========================
# CREATE ALERT CSV
# ==========================

if not os.path.exists("alerts.csv"):
    with open("alerts.csv", "w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            "Timestamp",
            "Source IP",
            "Destination IP",
            "Country",
            "City",
            "Attack Type",
            "Risk Level",
            "Confidence"
        ])

# ==========================
# LOAD MODEL
# ==========================

model = joblib.load(
    r"C:\Users\carol\OneDrive\Documents\AI_IDS_Project\ids_model.pkl"
)

# ==========================
# FLOW STORAGE
# ==========================

flows = defaultdict(lambda: {
    "start_time": time.time(),
    "packet_count": 0,
    "total_bytes": 0
})

attack_stats = defaultdict(int)

# ==========================
# ATTACK MAPPING
# ==========================

attack_mapping = {
    "BENIGN": "Normal",
    "Normal": "Normal",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS Slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "Portscan": "Port Scan",
    "Infiltration - Portscan": "Port Scan",
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "Brute Force": "Brute Force",
    "Botnet": "Botnet",
    "Web Attack": "Web Attack",
    "Web Attack - XSS": "Web Attack",
    "Web Attack - SQL Injection": "Web Attack",
    "Web Attack - Brute Force": "Web Attack"
}

risk_mapping = {
    "Normal": "Low",
    "Port Scan": "Medium",
    "Brute Force": "High",
    "Web Attack": "High",
    "DoS": "High",
    "DDoS": "Critical",
    "Botnet": "Critical"
}

# ==========================
# TSHARK COMMAND
# ==========================

cmd = [
    r"C:\Program Files\Wireshark\tshark.exe",
    "-i",
    "5",
    "-T",
    "fields",
    "-e",
    "ip.src",
    "-e",
    "ip.dst",
    "-e",
    "tcp.dstport",
    "-e",
    "frame.len"
]

print("Starting Real-Time IDS...\n")

process = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

# ==========================
# MAIN LOOP
# ==========================

for line in process.stdout:

    fields = line.strip().split("\t")

    if len(fields) < 4:
        continue

    src_ip = fields[0]
    dst_ip = fields[1]

    try:
        dst_port = int(fields[2])
        packet_len = int(fields[3])
    except:
        continue

    flow_id = f"{src_ip}-{dst_ip}-{dst_port}"

    flows[flow_id]["packet_count"] += 1
    flows[flow_id]["total_bytes"] += packet_len

    duration = time.time() - flows[flow_id]["start_time"]

    if duration > 5:

        packets = flows[flow_id]["packet_count"]
        total_bytes = flows[flow_id]["total_bytes"]

        avg_packet_size = total_bytes / packets
        packets_per_sec = packets / duration
        bytes_per_sec = total_bytes / duration

        sample = pd.DataFrame([{
            "Flow Duration": duration,
            "Dst Port": dst_port,
            "Flow Bytes/s": bytes_per_sec,
            "Flow Packets/s": packets_per_sec,
            "Packet Length Mean": avg_packet_size,
            "Average Packet Size": avg_packet_size
        }])

        prediction = model.predict(sample)[0]

        probabilities = model.predict_proba(sample)[0]
        confidence = max(probabilities) * 100

        main_attack = attack_mapping.get(
            prediction,
            prediction
        )

        attack_stats[main_attack] += 1

        risk_level = risk_mapping.get(
            main_attack,
            "Unknown"
        )

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        country, city = get_location(src_ip)

        print("\n====================================")
        print("TIMESTAMP :", timestamp)
        print("SOURCE IP :", src_ip)
        print("DEST IP   :", dst_ip)
        print("COUNTRY   :", country)
        print("CITY      :", city)
        print("FLOW      :", flow_id)
        print()

        if main_attack == "Normal":

            print("STATUS : NORMAL TRAFFIC")
            print("RISK LEVEL : Low")
            print("CONFIDENCE :", round(confidence, 2), "%")

            with open("alerts.csv", "a", newline="") as f:

                writer = csv.writer(f)

                writer.writerow([
                    timestamp,
                    src_ip,
                    dst_ip,
                    country,
                    city,
                    main_attack,
                    "Low",
                    round(confidence, 2)
                ])

        else:

            print("ALERT DETECTED!")
            print("ATTACK TYPE:", main_attack)
            print("RISK LEVEL :", risk_level)
            print("CONFIDENCE :", round(confidence, 2), "%")

            print("\nReason:")
            print("Packets/s       =", round(packets_per_sec, 2))
            print("Flow Duration   =", round(duration, 2))
            print("Avg Packet Size =", round(avg_packet_size, 2))

            with open("alerts.csv", "a", newline="") as f:

                writer = csv.writer(f)

                writer.writerow([
                    timestamp,
                    src_ip,
                    dst_ip,
                    country,
                    city,
                    main_attack,
                    risk_level,
                    round(confidence, 2)
                ])

        print("\nATTACK STATISTICS")

        for attack, count in attack_stats.items():
            print(f"{attack}: {count}")

        print("====================================")

        flows[flow_id] = {
            "start_time": time.time(),
            "packet_count": 0,
            "total_bytes": 0
        }