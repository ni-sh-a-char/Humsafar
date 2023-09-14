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
import folium
import requests
import json

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
    # IDS code here

# Function to get geolocation data for an IP address
def get_geolocation(ip_address, api_key):
    url = f"https://ipinfo.io/{ip_address}/json?token={api_key}"

    response = requests.get(url)
    if response.status_code == 200:
        data = json.loads(response.text)
        return data
    else:
        return None

# Function to integrate Humsafar web browser
def humsafar_web_browser():
    st.subheader("Humsafar Web Browser")
    st.write("Enter a URL to browse the web.")
    url = st.text_input("URL:")
    if st.button("Go"):
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        st.components.v1.iframe(url)

# Streamlit app
st.title("Packet Capture Analyzer and IDS")

# Add a menu entry for IDS
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
    intrusion_detection(network_interface, suspicious_ip_list)
elif menu_option == "IP Geolocation":
    st.subheader("IP Geolocation")
    source_ip = st.text_input("Enter Source IP Address:")
    destination_ip = st.text_input("Enter Destination IP Address:")
    api_key = st.text_input("Enter your API key for geolocation services")
    if source_ip and destination_ip:
        source_location_data = get_geolocation(source_ip, api_key)
        destination_location_data = get_geolocation(destination_ip, api_key)
        if source_location_data and destination_location_data:
            source_city = source_location_data.get("city", "N/A")
            source_country = source_location_data.get("country", "N/A")
            source_loc = source_location_data.get("loc", "0,0").split(",")
            source_latitude = float(source_loc[0])
            source_longitude = float(source_loc[1])

            destination_city = destination_location_data.get("city", "N/A")
            destination_country = destination_location_data.get("country", "N/A")
            destination_loc = destination_location_data.get("loc", "0,0").split(",")
            destination_latitude = float(destination_loc[0])
            destination_longitude = float(destination_loc[1])

            st.subheader("Source Location:")
            st.write(f"City: {source_city}")
            st.write(f"Country: {source_country}")

            st.subheader("Destination Location:")
            st.write(f"City: {destination_city}")
            st.write(f"Country: {destination_country}")

            m = folium.Map(location=[source_latitude, source_longitude], zoom_start=4)
            folium.Marker([source_latitude, source_longitude], tooltip=f"Source: {source_city}, {source_country}", icon=folium.Icon(color="green")).add_to(m)
            folium.Marker([destination_latitude, destination_longitude], tooltip=f"Destination: {destination_city}, {destination_country}", icon=folium.Icon(color="red")).add_to(m)

            st.subheader("Map:")
            folium_static(m)
        else:
            st.error("Unable to retrieve geolocation data for one or both IP addresses.")
elif menu_option == "Humsafar Web Browser":
    humsafar_web_browser()
