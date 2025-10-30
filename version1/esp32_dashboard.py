import streamlit as st
import pandas as pd
import plotly.express as px
import serial
import time

# Set Serial Port (Update this based on your OS)
SERIAL_PORT = "/dev/ttyUSB0"  # Linux/macOS (Use "COM3" for Windows)
BAUD_RATE = 115200

# Try connecting to ESP32 Serial
try:
    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
    time.sleep(2)  # Give some time to establish connection
    st.success(f"Connected to ESP32 on {SERIAL_PORT} ✅")
except Exception as e:
    st.error(f"Failed to connect to ESP32: {e} ❌")
    ser = None

# Streamlit UI
st.set_page_config(page_title="ESP32 Attack Detection", layout="wide")

st.title("🔍 ESP32 Cyberattack Detection Dashboard")
st.markdown("#### 📡 Real-time AI-based Network Attack Monitoring")

# Store incoming data
data = []

# Attack class mapping
attack_types = {0: "Normal", 1: "Suspicious", 2: "Confirmed Attack"}
attack_colors = {0: "green", 1: "orange", 2: "red"}

# Stream Data from ESP32
def read_serial_data():
    """Read and parse serial data from ESP32."""
    try:
        if ser and ser.in_waiting:
            line = ser.readline().decode("utf-8").strip()
            parts = line.split(",")
            if len(parts) == 12:  # Ensure correct format
                timestamp = int(parts[0])
                protocol = int(parts[1])
                src_port = int(parts[2])
                dest_port = int(parts[3])
                packet_size = int(parts[4])
                ttl = int(parts[5])
                tcp_flags = int(parts[6])
                payload_size = int(parts[7])
                interarrival_time = int(parts[8])
                packet_count = int(parts[9])
                predicted_class = int(parts[10])

                return {
                    "Timestamp": timestamp,
                    "Protocol": protocol,
                    "Source Port": src_port,
                    "Destination Port": dest_port,
                    "Packet Size": packet_size,
                    "TTL": ttl,
                    "TCP Flags": tcp_flags,
                    "Payload Size": payload_size,
                    "Interarrival Time": interarrival_time,
                    "Packet Count": packet_count,
                    "Attack Type": attack_types.get(predicted_class, "Unknown"),
                }
    except Exception as e:
        st.warning(f"Error reading serial data: {e}")
        return None

# Display Data in Table
data_placeholder = st.empty()
chart_placeholder = st.empty()

# Live Stream Data
while True:
    new_data = read_serial_data()
    if new_data:
        data.append(new_data)

        # Convert to DataFrame
        df = pd.DataFrame(data)
        
        # Show Data Table
        data_placeholder.dataframe(df.tail(10))  # Show last 10 records

        # Line Chart for Attack Types
        fig = px.scatter(
            df,
            x="Timestamp",
            y="Packet Size",
            color="Attack Type",
            title="📊 Attack Predictions Over Time",
            color_discrete_map=attack_colors,
        )
        chart_placeholder.plotly_chart(fig, use_container_width=True)

        # Show Alerts for Attacks
        if new_data["Attack Type"] == "Confirmed Attack":
            st.error("🚨 **ALERT: Cyberattack Detected!** 🚨")
        elif new_data["Attack Type"] == "Suspicious":
            st.warning("⚠️ **Warning: Suspicious Activity Detected!** ⚠️")

    time.sleep(1)  # Streamlit loop delay
