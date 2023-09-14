import sys
import logging
from scapy.all import *

# Network interface to monitor (replace with your network interface name, e.g., "eth0")
network_interface = "<network_interface>"

# Log file for IDS alerts (replace with your desired log file path)
log_file = "ids_alerts.log"

# Customize the log format and alert severity level
log_format = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(filename=log_file, format=log_format, level=logging.INFO)

# Customize the threshold for intrusion detection
intrusion_threshold = 10  # Adjust as needed

# Dictionary to store packet counts
packet_counts = {}

# Dictionary to store failed login attempts
failed_login_attempts = {}

# Dictionary to store port scanning detection
port_scanning_detected = {}

# List of suspicious IP addresses
suspicious_ip_list = ["<suspicious_ip_1>", "<suspicious_ip_2>"]

# Function to log IDS alerts
def log_alert(message, severity):
    # Customize the alert message format
    alert_message = f"[{severity}] {message}"
    print(alert_message)
    logging.info(alert_message)

# Signature-Based Detection
def signature_detection(packet):
    if "SQL Injection" in str(packet.payload):
        log_alert("SQL Injection detected (Signature-Based)", "HIGH")
        return True
    return False

# Anomaly-Based Detection
def anomaly_detection(packet):
    global packet_counts

    # Traffic Baselines
    baseline = 1000  # Replace with your baseline value
    threshold = 200  # Replace with your threshold value

    src_ip = packet[IP].src
    if src_ip in packet_counts:
        packet_counts[src_ip] += 1
    else:
        packet_counts[src_ip] = 1

    if packet_counts[src_ip] > baseline + threshold:
        log_alert(f"Unusual traffic volume from {src_ip} (Anomaly-Based)", "MEDIUM")
        return True

    # Protocol Anomalies
    if packet.haslayer(TCP) and packet[TCP].dport == 80 and packet[IP].proto != 6:
        log_alert("Protocol anomaly detected (Anomaly-Based)", "LOW")
        return True

    # Rate Limiting (assuming it's a login attempt)
    rate_limit = 10  # Replace with your rate limit
    if packet.haslayer(Raw) and "login_attempt" in str(packet[Raw].load):
        if src_ip in packet_counts and packet_counts[src_ip] > rate_limit:
            log_alert("Rate limit exceeded for login attempts (Anomaly-Based)", "MEDIUM")
            return True

    return False

# Behavior-Based Detection
def behavior_detection(packet):
    global failed_login_attempts
    global port_scanning_detected

    # User Behavior (assuming it's a failed login attempt)
    if packet.haslayer(Raw) and "failed_login" in str(packet[Raw].load):
        src_ip = packet[IP].src
        if src_ip in failed_login_attempts:
            failed_login_attempts[src_ip] += 1
        else:
            failed_login_attempts[src_ip] = 1

        if failed_login_attempts[src_ip] > 5:
            log_alert(f"Excessive failed login attempts from {src_ip} (Behavior-Based)", "MEDIUM")
            return True

    # Host Behavior (assuming it's a port scanning attempt)
    if packet.haslayer(Raw) and "port_scan" in str(packet[Raw].load):
        src_ip = packet[IP].src
        port_scanning_detected[src_ip] = True
        log_alert(f"Port scanning detected from {src_ip} (Behavior-Based)", "HIGH")
        return True

    return False

# Machine Learning-Based Detection (placeholder function)
def is_normal_traffic_pattern(predicted_traffic):
    # Replace with your machine learning-based detection logic
    return False

# Custom Rules
def custom_rule_detection(packet):
    dst_ip = packet[IP].dst
    if dst_ip in suspicious_ip_list:
        log_alert(f"Suspicious traffic to {dst_ip} (Custom Rule-Based)", "MEDIUM")
        return True
    return False

# Sniff network traffic and detect intrusions
try:
    print("Starting IDS (Ctrl+C to stop)...")
    sniff(iface=network_interface, prn=lambda x: any([
        signature_detection(x),
        anomaly_detection(x),
        behavior_detection(x),
        custom_rule_detection(x),
    ]))
except KeyboardInterrupt:
    print("IDS stopped.")
