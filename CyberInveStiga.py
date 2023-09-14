import streamlit as st
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io
import os
from docx2txt import process
import logging
from scapy.all import *

# Function to read and visualize packet capture data using pyshark
def analyze_packet_capture(file, fields_to_visualize):
    st.subheader("Packet Capture Analysis")

    # Create an empty DataFrame to store selected fields
    df = pd.DataFrame(columns=fields_to_visualize)

    if file.name.endswith((".pcap", ".pcapng")):
        # Read packet capture file using PyShark
        capture = pyshark.FileCapture(file)

        # Extract data and populate the DataFrame
        for packet in capture:
            packet_data = {}
            for field in fields_to_visualize:
                if field in packet:
                    packet_data[field] = packet[field]
                else:
                    packet_data[field] = None
            df = df.append(packet_data, ignore_index=True)
    else:
        # Read user-provided text, CSV, XLS, XLSX, or DOCX file formats
        if file.name.endswith(".txt"):
            content = file.read()
            lines = content.splitlines()
            df = pd.DataFrame(lines, columns=["Data"])
        elif file.name.endswith((".csv", ".xls", ".xlsx")):
            # Process CSV, XLS, and XLSX files using pandas
            df = pd.read_csv(file) if file.name.endswith(".csv") else pd.read_excel(file)
        elif file.name.endswith(".docx"):
            # Process DOCX files using docx2txt
            text = process(file)
            lines = text.splitlines()
            df = pd.DataFrame(lines, columns=["Data"])
        else:
            st.error("Unsupported file format. Please upload a supported file.")
            return

    # Visualize the selected fields
    for field in fields_to_visualize:
        st.subheader(f"Visualization for {field}")
        plt.figure(figsize=(10, 6))
        if df[field].dtype == "object":
            # For string data, create a bar chart of value counts
            value_counts = df[field].value_counts()
            plt.bar(value_counts.index, value_counts.values)
            plt.xticks(rotation=45, ha="right")
        else:
            # For numeric data, create a histogram
            plt.hist(df[field].dropna(), bins=20)
        plt.xlabel(field)
        plt.ylabel("Count")
        plt.title(f"{field} Distribution")
        st.pyplot(plt)

    # Generate PDF report
    st.subheader("Generate PDF Report")
    pdf_report = st.button("Generate PDF Report")
    if pdf_report:
        pdf_filename = "packet_capture_analysis.pdf"
        user_report_content = st.text_area("Enter your custom report content (optional)")
        generate_pdf_report(pdf_filename, df, fields_to_visualize, user_report_content)

# Function to generate a PDF report
def generate_pdf_report(filename, df, fields_to_visualize, user_report_content):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.drawString(100, 750, "Packet Capture Analysis Report")
    c.drawString(100, 730, "Fields Analyzed:")
    y_position = 710
    for field in fields_to_visualize:
        c.drawString(120, y_position, field)
        y_position -= 20

    # Create a table from the DataFrame
    df_table = df.head(10).to_string()

    y_position -= 30
    c.drawString(100, y_position, "Top 10 Data Records:")
    y_position -= 20
    for line in df_table.split("\n"):
        c.drawString(120, y_position, line)
        y_position -= 20

    # Add custom user report content
    if user_report_content:
        y_position -= 30
        c.drawString(100, y_position, "User Report:")
        user_report_lines = user_report_content.split("\n")
        for line in user_report_lines:
            y_position -= 20
            c.drawString(120, y_position, line)

    c.save()

    buffer.seek(0)
    with open(filename, "wb") as f:
        f.write(buffer.read())
    st.success(f"PDF Report '{filename}' generated successfully!")

# Function for IDS
def intrusion_detection(network_interface, suspicious_ip_list):
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

# Streamlit app
st.title("Packet Capture Analyzer and IDS")

# Add a menu entry for IDS
menu_option = st.sidebar.selectbox("Select an option", ["Packet Capture Analysis", "Intrusion Detection"])
if menu_option == "Packet Capture Analysis":
    uploaded_file = st.file_uploader("Upload a packet capture or text file", type=["pcap", "pcapng", "txt", "csv", "xls", "xlsx", "docx"])
    if uploaded_file is not None:
        fields_to_visualize = st.multiselect(
            "Select fields to visualize",
            ["ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "http.request.uri", "http.response.code"],
        )
        analyze_packet_capture(uploaded_file, fields_to_visualize)
elif menu_option == "Intrusion Detection":
    st.subheader("Intrusion Detection Settings")
    network_interface = st.text_input("Enter the network interface to monitor (e.g., 'eth0')")
    suspicious_ip_list = st.text_area("Enter suspicious IP addresses (comma-separated)", "")
    suspicious_ip_list = [ip.strip() for ip in suspicious_ip_list.split(",")]
    intrusion_detection(network_interface, suspicious_ip_list)
