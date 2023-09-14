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
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

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
def intrusion_detection(network_interface, suspicious_ip_list, pcap_file):
    # Log file for IDS alerts (replace with your desired log file path)
    log_file = "ids_alerts.log"

    # Customize the log format and alert severity level
    log_format = "%(asctime)s [%(levelname)s] %(message)s"
    logging.basicConfig(filename=log_file, format=log_format, level=logging.INFO)

    # Load machine learning models
    rf_model = RandomForestClassifier()
    gb_model = GradientBoostingClassifier()
    svm_model = SVC()

    # Load the dataset and labels (you need to provide the data preprocessing step)
    # For demonstration, let's assume you have X_train, y_train, X_test, and y_test

    # Train the models
    rf_model.fit(X_train, y_train)
    gb_model.fit(X_train, y_train)
    svm_model.fit(X_train, y_train)

    # Predict using the models
    rf_predictions = rf_model.predict(X_test)
    gb_predictions = gb_model.predict(X_test)
    svm_predictions = svm_model.predict(X_test)

    # Combine predictions using majority voting
    combined_predictions = (rf_predictions + gb_predictions + svm_predictions) >= 2

    # Calculate accuracy of the combined predictions
    accuracy = accuracy_score(y_test, combined_predictions)

    # Print the accuracy
    print(f"Combined Model Accuracy: {accuracy}")

    # Rest of the IDS code goes here...

# Streamlit app
st.title("Packet Capture Analyzer and IDS")

# Add a sidebar menu for different app options
menu_option = st.sidebar.selectbox("Select an option", ["Packet Capture Analysis", "Intrusion Detection", "IP Geolocation", "Humsafar Web Browser"])

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
    pcap_file = st.file_uploader("Upload a PCAP file for intrusion detection", type=["pcap", "pcapng"])
    intrusion_detection(network_interface, suspicious_ip_list, pcap_file)
elif menu_option == "IP Geolocation":
    st.subheader("IP Geolocation")
    # Implement IP geolocation functionality here
    # You can add input fields and a button to perform geolocation
    # Display the results to the user
elif menu_option == "Humsafar Web Browser":
    st.subheader("Humsafar Web Browser")
    # Implement Humsafar web browser functionality here
    # You can use the provided code for the web browser and integrate it here

