import streamlit as st
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io
import os
from docx2txt import process

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

# Streamlit app
st.title("Packet Capture Analyzer")

# Add a file upload widget
uploaded_file = st.file_uploader("Upload a packet capture or text file", type=["pcap", "pcapng", "txt", "csv", "xls", "xlsx", "docx"])

if uploaded_file is not None:
    fields_to_visualize = st.multiselect(
        "Select fields to visualize",
        ["ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "http.request.uri", "http.response.code"],
    )

    # Analyze the uploaded data
    analyze_packet_capture(uploaded_file, fields_to_visualize)