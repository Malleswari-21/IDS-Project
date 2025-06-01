# IDS-Project
import streamlit as st
import scapy.all as scapy
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
import threading
import pandas as pd
import time

# Global Variables
packet_logs = []
alerts = []
custom_rules = []
sent_alerts = set()  # To limit duplicate email alerts per session
alert_threshold = 10
baseline_traffic = {}
signature_database = [
    {'pattern': 'SYN flood', 'protocol': 6},
    {'pattern': 'ARP spoof', 'protocol': 2054}
]

# Control Flags
stop_flag = threading.Event()

# Packet Capture and Analysis
def capture_packets():
    def process_packet(packet):
        if stop_flag.is_set():
            return
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            protocol = packet[scapy.IP].proto\
            timestamp = datetime.now()

            # Log the packet
            packet_logs.append((timestamp, src_ip, dst_ip, protocol))

            # Perform anomaly and signature detection
            check_anomalies(src_ip, dst_ip)
            check_signatures(src_ip, dst_ip, protocol)

    scapy.sniff(prn=process_packet, store=False, stop_filter=lambda x: stop_flag.is_set())

# Signature-Based Detection
def check_signatures(src_ip, dst_ip, protocol):
    for signature in signature_database:
        if protocol == signature['protocol']:
            alert_message = f"Detected: {signature['pattern']} from {src_ip} to {dst_ip}"
            if alert_message not in sent_alerts:
                alerts.append((datetime.now(), src_ip, dst_ip, signature['pattern']))
                send_alert(alert_message)
                sent_alerts.add(alert_message)

# Anomaly Detection
def check_anomalies(src_ip, dst_ip):
    global baseline_traffic
    key = f"{src_ip}-{dst_ip}"
    baseline_traffic[key] = baseline_traffic.get(key, 0) + 1

    if baseline_traffic[key] > alert_threshold:
        alert_message = f"Anomalous traffic from {src_ip} to {dst_ip}"
        if alert_message not in sent_alerts:
            alerts.append((datetime.now(), src_ip, dst_ip, 'Anomaly detected'))
            send_alert(alert_message)
            sent_alerts.add(alert_message)

# Send Alerts via Email with Rate Limiting
def send_alert(message):
    try:
        sender = "malleswarigottipati404@gmail.com"
        receiver = "pasamkoteswararao07@gmail.com"  # Corrected domain to gmail.com
        password = "asrv keul kmcu zdzj"  # Replace with the generated App Password

        msg = MIMEText(message)
        msg['Subject'] = "Intrusion Detection Alert"
        msg['From'] = sender
        msg['To'] = receiver

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender, password)
            server.sendmail(sender, receiver, msg.as_string())
            print(f"Alert sent: {message}")
        
        # Add a small delay to prevent overwhelming the server
        time.sleep(1)
    except smtplib.SMTPException as e:
        print(f"SMTP error: {e}")
    except Exception as e:
        print(f"Error sending alert: {e}")

# Streamlit Dashboard with Dynamic Updates
def main():
    st.title("Intrusion Detection System")

    # Dynamic placeholders for packet logs, alerts, and rules
    logs_placeholder = st.empty()
    alerts_placeholder = st.empty()
    rules_placeholder = st.empty()

    # Start/Stop Buttons
    if st.button("Start Detection"):
        stop_flag.clear()
        threading.Thread(target=capture_packets, daemon=True).start()

    if st.button("Stop Detection"):
        stop_flag.set()

    # Custom Rule Creation
    st.subheader("Custom Rule Creation")
    src_ip = st.text_input("Source IP")
    dst_ip = st.text_input("Destination IP")
    if st.button("Add Rule"):
        rule = {'Source IP': src_ip, 'Destination IP': dst_ip}
        custom_rules.append(rule)
        alert_message = f"Custom rule triggered: {src_ip} -> {dst_ip}"
        alerts.append((datetime.now(), src_ip, dst_ip, "Custom Rule Triggered"))
        if alert_message not in sent_alerts:
            send_alert(alert_message)
            sent_alerts.add(alert_message)

    # Continuously update the interface while detection is running
    while not stop_flag.is_set():
        # Update packet logs dynamically
        logs_placeholder.subheader("Packet Logs")
        packet_df = pd.DataFrame(packet_logs, columns=['Timestamp', 'Source IP', 'Destination IP', 'Protocol'])
        logs_placeholder.dataframe(packet_df)

        # Update alerts dynamically
        alerts_placeholder.subheader("Alerts"\jnjmnnmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm'             '0 '
        alerts_df = pd.DataFrame(alerts, columns=['Timestamp', 'Source IP', 'Destination IP', 'Alert Type'])
        alerts_placeholder.dataframe(alerts_df)

        # Update custom rules dynamically
        rules_placeholder.subheader("Custom Rules")
        rules_df = pd.DataFrame(custom_rules)
        rules_placeholder.dataframe(rules_df)

        # Refresh the UI every second
        time.sleep(1)

    # Final update when the detection stops
    st.success("Detection stopped.")
    logs_placeholder.dataframe(pd.DataFrame(packet_logs, columns=['Timestamp', 'Source IP', 'Destination IP', 'Protocol']))
    alerts_placeholder.dataframe(pd.DataFrame(alerts, columns=['Timestamp', 'Source IP', 'Destination IP', 'Alert Type']))
    rules_placeholder.dataframe(pd.DataFrame(custom_rules))

# Main Function
if _name_ == "_main_":
    main()
