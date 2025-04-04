ESP32 Real-Time Cyberattack Detection using TinyML

🚀 Real-time network attack detection using ESP32 in promiscuous mode and a trained deep learning model (TinyML). This project captures WiFi packets, extracts key features, classifies them as normal or attack traffic using a lightweight neural network, and triggers alerts.

📌 Project Overview:

This project detects cyberattacks (e.g., SYN Flood, UDP Flood, ICMP Flood, Port Scans) in real-time using ESP32 as a packet sniffer and a pre-trained neural network (converted to C array format for deployment). The attack classification results are logged and analyzed using Python & Scapy.

🔹 Key Features:

✔ ESP32 in WiFi Promiscuous Mode for packet sniffing

✔ Feature extraction (Protocol, Ports, TTL, Packet Size, etc.)

✔ TinyML Model for cyberattack classification

✔ Alerts on detected attacks via Serial Monitor

✔ Python-based attack traffic generator

✔ Live logging to CSV for analysis
