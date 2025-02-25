## wifi_scan.py ##
# wifi anylyzer application
#application structure:

wifi_analyzer/
│
├── app.py               # Main Streamlit app
├── network_scanner.py   # Scans connected devices
├── ping_util.py         # Ping functionality
├── stats_monitor.py     # Real-time networking statistics
├── wifi_info.py         # Detects SSID and channel
├── requirements.txt     # List of dependencies

# main coding that makes the application:

import streamlit as st
import subprocess
import re
import scapy.all as scapy
from ping3 import ping
import psutil
import time

# ------------------ Wi-Fi Info Function ------------------ #
def get_wifi_info():
    try:
        result = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True)
        ssid_match = re.search(r'SSID\s*:\s(.*)', result)
        channel_match = re.search(r'Channel\s*:\s(\d+)', result)

        ssid = ssid_match.group(1).strip() if ssid_match else "Unknown"
        channel = channel_match.group(1).strip() if channel_match else "Unknown"
        return ssid, channel
    except Exception as e:
        return "Error", str(e)

# ------------------ Network Scanner Function ------------------ #
def scan_network(ip_range="192.168.1.1/24"):
    devices = []
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    for element in answered:
        device_info = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc
        }
        devices.append(device_info)
    return devices

# ------------------ Ping Function ------------------ #
def ping_host(host):
    try:
        delay = ping(host, timeout=2)
        if delay:
            return f"Ping to {host} successful! Delay: {round(delay * 1000, 2)} ms"
        else:
            return f"Ping to {host} failed."
    except Exception as e:
        return f"Error: {str(e)}"

# ------------------ Network Stats Function ------------------ #
def get_network_stats():
    stats = psutil.net_io_counters()
    return {
        "bytes_sent": stats.bytes_sent,
        "bytes_recv": stats.bytes_recv,
        "packets_sent": stats.packets_sent,
        "packets_recv": stats.packets_recv
    }

# ------------------ Streamlit UI ------------------ #
st.set_page_config(page_title="Wi-Fi Analyzer", layout="wide")
st.title("Wi-Fi Analyzer for Windows")

# Wi-Fi Information Section
st.subheader("Wi-Fi Info")
ssid, channel = get_wifi_info()
st.write(f"**SSID:** {ssid}")
st.write(f"**Channel:** {channel}")
if st.button("Copy SSID"):
    st.write(f"Copied: {ssid}")

# Network Scanner Section
st.subheader("Connected Devices")
if st.button("Scan Network"):
    devices = scan_network()
    if devices:
        for device in devices:
            st.write(f"IP: {device['ip']} | MAC: {device['mac']}")
    else:
        st.write("No devices found.")

# Ping Functionality Section
st.subheader("Ping a Host")
host = st.text_input("Enter IP/Hostname")
if st.button("Ping"):
    result = ping_host(host)
    st.write(result)

# Real-Time Network Stats Section
st.subheader("Real-Time Network Statistics")
stats_placeholder = st.empty()
refresh_rate = st.slider("Refresh Rate (seconds)", 1, 10, 2)

# Live Updating Stats
while True:
    stats = get_network_stats()
    stats_placeholder.write(
        f"Bytes Sent: {stats['bytes_sent']} | Bytes Received: {stats['bytes_recv']} | "
        f"Packets Sent: {stats['packets_sent']} | Packets Received: {stats['packets_recv']}"
    )
    time.sleep(refresh_rate)
