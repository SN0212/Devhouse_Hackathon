#include <stdio.h>
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <vector>
#include <unordered_map>

#define SERIAL_BAUD 115200

const char *ssid = "IoT";
const char *password = "12345678";

volatile uint32_t lastTimestamp = 0;
volatile uint32_t packetCount = 0;

void snifferCallback(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA)
        return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *data = pkt->payload;
    uint16_t packetSize = pkt->rx_ctrl.sig_len;

    uint32_t timestamp = micros();
    uint32_t interarrivalTime = (lastTimestamp == 0) ? 0 : (timestamp - lastTimestamp);
    lastTimestamp = timestamp;

    packetCount++;

    if (packetSize < 34)
        return; // Ignore non-IP packets

    uint8_t protocol = data[23]; // IP Protocol (TCP=6, UDP=17, ICMP=1)
    uint8_t ttl = data[22];
    uint16_t totalLength = (data[16] << 8) | data[17];
    uint16_t headerLength = (data[14] & 0x0F) * 4;
    uint16_t payloadSize = totalLength - headerLength;

    char sourceIP[16], destIP[16];
    sprintf(sourceIP, "%d.%d.%d.%d", data[26], data[27], data[28], data[29]);
    sprintf(destIP, "%d.%d.%d.%d", data[30], data[31], data[32], data[33]);

    uint16_t srcPort = 0, destPort = 0, tcpFlags = 0;
    if (protocol == 6 || protocol == 17)
    {
        srcPort = (data[headerLength + 14] << 8) | data[headerLength + 15];
        destPort = (data[headerLength + 16] << 8) | data[headerLength + 17];
    }
    if (protocol == 6)
    {
        tcpFlags = data[headerLength + 13];
    }

    // Send extracted data via Serial
    Serial.printf("%lu,%s,%s,%d,%d,%d,%d,%d,%d,%d,%lu,%lu\n",
                  timestamp, sourceIP, destIP, protocol, srcPort, destPort,
                  packetSize, ttl, tcpFlags, payloadSize, interarrivalTime, packetCount);

    // Collecting predictions from 10 decision trees
    vector<int> predictions = {
        classify_packet1(timestamp, packet_size, payload_size, packet_count, interarrival_time, destination_port, ttl),
        classify_packet2(interarrival_time, timestamp, payload_size, destination_port, packet_size, packet_count, ttl),
        classify_packet3(interarrival_time, payload_size, destination_port, packet_size, packet_count, ttl),
        classify_packet4(interarrival_time, payload_size, destination_port, packet_size, packet_count, timestamp),
        classify_packet5(packet_count, source_port, packet_size, timestamp, interarrival_time, destination_port, ttl, payload_size),
        classify_packet6(packet_size, timestamp, ttl, payload_size, destination_port, interarrival_time),
        classify_packet7(interarrival_time, ttl, timestamp, packet_size, destination_port, payload_size, packet_count, protocol),
        classify_packet8(timestamp, destination_port, packet_size, interarrival_time, payload_size, ttl, packet_count, source_port),
        classify_packet9(interarrival_time, timestamp, packet_size, source_port, ttl, destination_port, payload_size, packet_count, protocol),
        classify_packet10(interarrival_time, timestamp, packet_size, source_port, ttl, destination_port, payload_size, packet_count, protocol)};

    // Determine final attack class using majority vote
    int final_attack_class = majority_vote(predictions);

    // Optional: add detection alerts
    if (attack_class == 0)
    {
        Serial.println("!!! ALERT: Possible DNS Query attack detected.");
    }
    if (attack_class == 1)
    {
        Serial.println("!!! ALERT: Possible HTTP Request attack detected.");
    }
    if (attack_class == 2)
    {
        Serial.println("!!! ALERT: Possible Malformed Packets attack detected.");
    }
    if (attack_class == 3)
    {
        Serial.println("Normal!");
    }
    if (attack_class == 4)
    {
        Serial.println("!!! ALERT: Possible Port Scan attack detected.");
    }
    if (attack_class == 5)
    {
        Serial.println("!!! ALERT: Possible SYN Flood attack detected.");
    }
    if (attack_class == 6)
    {
        Serial.println("!!! ALERT: Possible UDP Flood attack detected.");
    }
}

// Function to classify packet based on decision tree rules
int classify_packet1(float timestamp, int packet_size, int payload_size, int packet_count, float interarrival_time, float destination_port, int ttl)
{

    if (timestamp <= -0.72)
    {
        if (packet_size <= -0.46)
        {
            return 5; // Class 5
        }
        else
        {
            if (timestamp <= -0.93)
            {
                if (packet_count <= -1.16)
                {
                    if (destination_port <= 2.28)
                    {
                        if (payload_size <= 1.52)
                        {
                            return 3; // Class 3
                        }
                        else
                        {
                            if (packet_count <= -1.60)
                            {
                                return 6; // Class 6
                            }
                            else
                            {
                                return 6; // Class 6
                            }
                        }
                    }
                    else
                    {
                        return 3; // Class 3
                    }
                }
                else
                {
                    if (interarrival_time <= -0.48)
                    {
                        if (payload_size <= 1.52)
                        {
                            return 3; // Class 3
                        }
                        else
                        {
                            return 6; // Class 6
                        }
                    }
                    else
                    {
                        return 3; // Class 3
                    }
                }
            }
            else
            {
                return 3; // Class 3
            }
        }
    }
    else
    {
        if (payload_size <= -0.23)
        {
            if (payload_size <= -0.29)
            {
                if (destination_port <= -0.74)
                {
                    if (interarrival_time <= 0.20)
                    {
                        if (ttl <= 1.76)
                        {
                            if (packet_size <= -0.46)
                            {
                                return 4; // Class 4
                            }
                            else
                            {
                                return 3; // Class 3
                            }
                        }
                        else
                        {
                            return 3; // Class 3
                        }
                    }
                    else
                    {
                        if (packet_size <= -0.46)
                        {
                            return 4; // Class 4
                        }
                        else
                        {
                            return 3; // Class 3
                        }
                    }
                }
                else
                {
                    if (timestamp <= -0.64)
                    {
                        if (packet_count <= -0.58)
                        {
                            if (packet_size <= -0.46)
                            {
                                return 2; // Class 2
                            }
                            else
                            {
                                return 3; // Class 3
                            }
                        }
                        else
                        {
                            if (packet_size <= -0.46)
                            {
                                return 2; // Class 2
                            }
                            else
                            {
                                return 3; // Class 3
                            }
                        }
                    }
                    else
                    {
                        if (packet_size <= -0.46)
                        {
                            if (destination_port <= -0.71)
                            {
                                return 2; // Class 2
                            }
                            else
                            {
                                return 2; // Class 2
                            }
                        }
                        else
                        {
                            return 3; // Class 3
                        }
                    }
                }
            }
            else
            {
                return 0; // Class 0
            }
        }
        else
        {
            if (packet_size <= -0.37)
            {
                if (interarrival_time <= -0.47)
                {
                    return 1; // Class 1
                }
                else
                {
                    return 1; // Class 1
                }
            }
            else
            {
                return 3; // Class 3
            }
        }
    }
}

int classify_packet2(float interarrivalTime, float timestamp, int payloadSize, float destinationPort, int packetSize, int packetCount, int ttl)
{
    if (interarrivalTime <= 3.09)
    {
        if (timestamp <= -0.93)
        {
            if (payloadSize <= 1.52)
            {
                return 3;
            }
            else
            {
                if (interarrivalTime <= -0.50)
                {
                    return 6;
                }
                else
                {
                    return 6;
                }
            }
        }
        else
        {
            if (destinationPort <= -0.79)
            {
                if (packetSize <= -0.37)
                {
                    if (packetSize <= -0.41)
                    {
                        if (interarrivalTime <= 0.37)
                        {
                            if (packetCount <= 0.20)
                            {
                                return 3;
                            }
                            else
                            {
                                if (interarrivalTime <= -0.21)
                                {
                                    return 4;
                                }
                                else
                                {
                                    return 4;
                                }
                            }
                        }
                        else
                        {
                            if (interarrivalTime <= 0.62)
                            {
                                return 3;
                            }
                            else
                            {
                                if (packetCount <= 0.24)
                                {
                                    return 3;
                                }
                                else
                                {
                                    return 4;
                                }
                            }
                        }
                    }
                    else
                    {
                        if (interarrivalTime <= -0.47)
                        {
                            return 1;
                        }
                        else
                        {
                            return 1;
                        }
                    }
                }
                else
                {
                    return 3;
                }
            }
            else
            {
                if (ttl <= -0.86)
                {
                    if (packetSize <= -0.46)
                    {
                        if (ttl <= -2.30)
                        {
                            return 2;
                        }
                        else
                        {
                            return 2;
                        }
                    }
                    else
                    {
                        return 3;
                    }
                }
                else
                {
                    if (packetCount <= -0.70)
                    {
                        if (packetSize <= -0.46)
                        {
                            return 5;
                        }
                        else
                        {
                            if (destinationPort <= -0.71)
                            {
                                return 3;
                            }
                            else
                            {
                                return 3;
                            }
                        }
                    }
                    else
                    {
                        if (packetCount <= 0.28)
                        {
                            return 3;
                        }
                        else
                        {
                            if (packetCount <= 1.10)
                            {
                                if (packetSize <= -0.46)
                                {
                                    return 4;
                                }
                                else
                                {
                                    return 3;
                                }
                            }
                            else
                            {
                                if (packetSize <= -0.46)
                                {
                                    return 4;
                                }
                                else
                                {
                                    return 3;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
        if (timestamp <= 2.47)
        {
            if (destinationPort <= -0.79)
            {
                return 3;
            }
            else
            {
                return 3;
            }
        }
        else
        {
            return 0;
        }
    }
}

int classify_packet3(float interarrivalTime, int payloadSize, int destinationPort, int packetSize, int packetCount, int ttl)
{
    if (packetSize <= -0.50)
    {
        return 0;
    }
    else
    {
        if (payloadSize <= 1.57)
        {
            if (packetSize <= -0.46)
            {
                if (ttl <= -0.86)
                {
                    return 2;
                }
                else
                {
                    if (destinationPort <= -0.73)
                    {
                        return 4;
                    }
                    else
                    {
                        if (interarrivalTime <= -0.49)
                        {
                            return 5;
                        }
                        else
                        {
                            return 5;
                        }
                    }
                }
            }
            else
            {
                if (payloadSize <= -0.26)
                {
                    return 3;
                }
                else
                {
                    if (packetSize <= -0.37)
                    {
                        if (packetCount <= 0.21)
                        {
                            return 1;
                        }
                        else
                        {
                            return 1;
                        }
                    }
                    else
                    {
                        return 3;
                    }
                }
            }
        }
        else
        {
            if (packetCount <= -1.60)
            {
                return 6;
            }
            else
            {
                return 6;
            }
        }
    }
}

int classify_packet4(float interarrivalTime, int payloadSize, float destinationPort, int packetSize, int packetCount, float timestamp)
{
    if (destinationPort <= -0.79)
    {
        if (packetCount <= 0.90)
        {
            if (interarrivalTime <= 0.37)
            {
                if (packetSize <= -0.46)
                {
                    return 4;
                }
                else
                {
                    return 3;
                }
            }
            else
            {
                if (interarrivalTime <= 0.60)
                {
                    return 3;
                }
                else
                {
                    return 3;
                }
            }
        }
        else
        {
            return 0;
        }
    }
    else
    {
        if (packetSize <= -0.46)
        {
            if (timestamp <= -0.72)
            {
                return 5;
            }
            else
            {
                if (packetCount <= -0.00)
                {
                    return 2;
                }
                else
                {
                    return 4;
                }
            }
        }
        else
        {
            if (packetCount <= -1.15)
            {
                if (payloadSize <= 1.52)
                {
                    return 3;
                }
                else
                {
                    if (interarrivalTime <= -0.50)
                    {
                        return 6;
                    }
                    else
                    {
                        return 6;
                    }
                }
            }
            else
            {
                if (payloadSize <= -0.26)
                {
                    return 3;
                }
                else
                {
                    if (interarrivalTime <= 2.39)
                    {
                        if (packetSize <= -0.37)
                        {
                            if (timestamp <= -0.23)
                            {
                                return 1;
                            }
                            else
                            {
                                return 1;
                            }
                        }
                        else
                        {
                            return 3;
                        }
                    }
                    else
                    {
                        return 3;
                    }
                }
            }
        }
    }
}

int classify_packet5(int packet_count, float source_port, int packet_size, float timestamp, float interarrival_time, float destination_port, int ttl, double payload_size)
{
    if (packet_count <= 1.56)
    {
        if (packet_count <= -0.70)
        {
            if (source_port <= 0.80)
            {
                if (packet_size <= -0.46)
                {
                    return 5; // Class 5
                }
                else
                {
                    if (packet_count <= -1.15)
                    {
                        return 3; // Class 3
                    }
                    else
                    {
                        return 3; // Class 3
                    }
                }
            }
            else
            {
                if (packet_size <= 2.26)
                {
                    if (timestamp <= -0.58)
                    {
                        if (interarrival_time <= -0.50)
                        {
                            return 6; // Class 6
                        }
                        else
                        {
                            return 6; // Class 6
                        }
                    }
                    else
                    {
                        return 3; // Class 3
                    }
                }
                else
                {
                    if (destination_port <= -0.72)
                    {
                        return 3; // Class 3
                    }
                    else
                    {
                        return 3; // Class 3
                    }
                }
            }
        }
        else
        {
            if (packet_size <= -0.46)
            {
                if (ttl <= -0.86)
                {
                    return 2; // Class 2
                }
                else
                {
                    if (interarrival_time <= -0.48)
                    {
                        return 4; // Class 4
                    }
                    else
                    {
                        return 4; // Class 4
                    }
                }
            }
            else
            {
                if (payload_size <= -0.26)
                {
                    return 3; // Class 3
                }
                else
                {
                    if (packet_size <= -0.37)
                    {
                        if (packet_count <= 0.21)
                        {
                            return 1; // Class 1
                        }
                        else
                        {
                            return 1; // Class 1
                        }
                    }
                    else
                    {
                        return 3; // Class 3
                    }
                }
            }
        }
    }
    else
    {
        return 0; // Class 0
    }
}

int classify_packet6(int packet_size, float timestamp, int ttl, int payload_size, float destination_port, float interarrival_time)
{

    if (packet_size <= -0.50)
    {
        return 0; // Class 0
    }
    else
    {
        if (packet_size <= -0.46)
        {
            if (timestamp <= -0.72)
            {
                return 5; // Class 5
            }
            else
            {
                if (ttl <= -0.86)
                {
                    return 2; // Class 2
                }
                else
                {
                    return 4; // Class 4
                }
            }
        }
        else
        {
            if (payload_size <= 1.57)
            {
                if (destination_port <= -0.79)
                {
                    if (ttl <= 1.76)
                    {
                        if (interarrival_time <= 2.39)
                        {
                            if (payload_size <= -0.26)
                            {
                                return 3; // Class 3
                            }
                            else
                            {
                                if (timestamp <= 1.48)
                                {
                                    return 1; // Class 1
                                }
                                else
                                {
                                    return 1; // Class 1
                                }
                            }
                        }
                        else
                        {
                            return 3; // Class 3
                        }
                    }
                    else
                    {
                        return 3; // Class 3
                    }
                }
                else
                {
                    return 3; // Class 3
                }
            }
            else
            {
                return 6; // Class 6
            }
        }
    }
}

int classify_packet7(float interarrival_time, int ttl, float timestamp, int packet_size, float destination_port, int payload_size, int packet_count, int protocol)
{
    if (interarrival_time <= 3.09)
    {
        if (ttl <= -0.86)
        {
            if (timestamp <= -0.70)
            {
                if (interarrival_time <= 0.61)
                {
                    if (packet_size <= -0.46)
                    {
                        return 2; // Class 2
                    }
                    else
                    {
                        return 3; // Class 3
                    }
                }
                else
                {
                    return 3; // Class 3
                }
            }
            else
            {
                if (packet_size <= -0.46)
                {
                    if (destination_port <= -0.70)
                    {
                        return 2; // Class 2
                    }
                    else
                    {
                        return 2; // Class 2
                    }
                }
                else
                {
                    return 3; // Class 3
                }
            }
        }
        else
        {
            if (packet_size <= -0.46)
            {
                if (timestamp <= -0.72)
                {
                    return 5; // Class 5
                }
                else
                {
                    return 4; // Class 4
                }
            }
            else
            {
                if (destination_port <= -0.79)
                {
                    if (packet_size <= -0.37)
                    {
                        if (payload_size <= -0.26)
                        {
                            return 3; // Class 3
                        }
                        else
                        {
                            return 1; // Class 1
                        }
                    }
                    else
                    {
                        return 3; // Class 3
                    }
                }
                else
                {
                    if (packet_count <= -1.15)
                    {
                        if (interarrival_time <= -0.31)
                        {
                            if (payload_size <= 1.52)
                            {
                                return 3; // Class 3
                            }
                            else
                            {
                                return 6; // Class 6
                            }
                        }
                        else
                        {
                            if (packet_size <= 2.26)
                            {
                                return 6; // Class 6
                            }
                            else
                            {
                                return 3; // Class 3
                            }
                        }
                    }
                    else
                    {
                        return 3; // Class 3
                    }
                }
            }
        }
    }
    else
    {
        if (protocol <= 0.84)
        {
            return 3; // Class 3
        }
        else
        {
            return 0; // Class 0
        }
    }
}

int classify_packet8(float timestamp, float destination_port, int packet_size, float interarrival_time, int payload_size, int ttl, int packet_count, float source_port)
{
    if (timestamp <= 2.46)
    {
        if (destination_port <= -0.79)
        {
            if (packet_size <= -0.37)
            {
                if (interarrival_time <= 0.60)
                {
                    if (payload_size <= -0.26)
                    {
                        if (packet_size <= -0.46)
                        {
                            return 4;
                        }
                        else
                        {
                            return 3;
                        }
                    }
                    else
                    {
                        return 1;
                    }
                }
                else
                {
                    if (payload_size <= -0.26)
                    {
                        if (interarrival_time <= 0.61)
                        {
                            return 4;
                        }
                        else
                        {
                            return 3;
                        }
                    }
                    else
                    {
                        return 1;
                    }
                }
            }
            else
            {
                return 3;
            }
        }
        else
        {
            if (ttl <= -0.86)
            {
                if (timestamp <= -0.63)
                {
                    if (packet_size <= -0.46)
                    {
                        return 2;
                    }
                    else
                    {
                        return 3;
                    }
                }
                else
                {
                    return 3;
                }
            }
            else
            {
                if (source_port <= 0.80)
                {
                    if (timestamp <= -0.43)
                    {
                        if (packet_size <= -0.46)
                        {
                            return 5;
                        }
                        else
                        {
                            return 3;
                        }
                    }
                    else
                    {
                        if (packet_size <= -0.46)
                        {
                            return 4;
                        }
                        else
                        {
                            return 3;
                        }
                    }
                }
                else
                {
                    if (interarrival_time <= -0.38)
                    {
                        if (payload_size <= 1.52)
                        {
                            return 3;
                        }
                        else
                        {
                            return 6;
                        }
                    }
                    else
                    {
                        return 3;
                    }
                }
            }
        }
    }
    else
    {
        return 0;
    }
}

int classify_packet9(float interarrival_time, float timestamp, int packet_size, float source_port, int ttl, float destination_port, int payload_size, int packet_count, int protocol)
{
    if (interarrival_time <= 3.16)
    {
        if (timestamp <= -0.72)
        {
            if (packet_size <= -0.46)
            {
                return 5;
            }
            else
            {
                if (source_port <= 0.80)
                {
                    return 3;
                }
                else
                {
                    if (packet_size <= 2.26)
                    {
                        return 6;
                    }
                    else
                    {
                        return 3;
                    }
                }
            }
        }
        else
        {
            if (packet_size <= -0.46)
            {
                if (ttl <= -0.86)
                {
                    return 2;
                }
                else
                {
                    return 4;
                }
            }
            else
            {
                if (destination_port <= -0.79)
                {
                    if (payload_size <= -0.26)
                    {
                        return 3;
                    }
                    else
                    {
                        if (timestamp <= 1.44)
                        {
                            if (packet_count <= 1.34)
                            {
                                if (packet_size <= -0.37)
                                {
                                    return 1;
                                }
                                else
                                {
                                    return 3;
                                }
                            }
                            else
                            {
                                if (interarrival_time <= -0.42)
                                {
                                    return 1;
                                }
                                else
                                {
                                    return 1;
                                }
                            }
                        }
                        else
                        {
                            if (timestamp <= 1.49)
                            {
                                if (timestamp <= 1.48)
                                {
                                    return 1;
                                }
                                else
                                {
                                    return 3;
                                }
                            }
                            else
                            {
                                if (packet_size <= -0.37)
                                {
                                    return 1;
                                }
                                else
                                {
                                    return 3;
                                }
                            }
                        }
                    }
                }
                else
                {
                    return 3;
                }
            }
        }
    }
    else
    {
        if (protocol <= 0.84)
        {
            return 3;
        }
        else
        {
            return 0;
        }
    }
}

int classify_packet10(float interarrival_time, float timestamp, int packet_size, float source_port, int ttl, float destination_port, int payload_size, int packet_count, int protocol)
{
    if (payload_size <= 1.57)
    {
        if (payload_size <= -0.28)
        {
            if (ttl <= -0.86)
            {
                if (interarrival_time <= 0.61)
                {
                    if (destination_port <= 2.17)
                    {
                        if (timestamp <= -0.61)
                        {
                            if (packet_size <= -0.46)
                            {
                                return 2;
                            }
                            else
                            {
                                if (packet_count <= -0.70)
                                {
                                    return 3;
                                }
                                else
                                {
                                    return 3;
                                }
                            }
                        }
                        else
                        {
                            if (interarrival_time <= 0.60)
                            {
                                if (ttl <= -2.21)
                                {
                                    return 2;
                                }
                                else
                                {
                                    return 2;
                                }
                            }
                            else
                            {
                                return 2;
                            }
                        }
                    }
                    else
                    {
                        if (packet_size <= -0.46)
                        {
                            return 2;
                        }
                        else
                        {
                            if (ttl <= -2.30)
                            {
                                return 3;
                            }
                            else
                            {
                                return 3;
                            }
                        }
                    }
                }
                else
                {
                    if (packet_size <= -0.46)
                    {
                        return 2;
                    }
                    else
                    {
                        if (ttl <= -2.30)
                        {
                            return 3;
                        }
                        else
                        {
                            return 3;
                        }
                    }
                }
            }
            else
            {
                if (packet_size <= -0.46)
                {
                    if (packet_count <= -0.70)
                    {
                        return 5;
                    }
                    else
                    {
                        return 4;
                    }
                }
                else
                {
                    return 3;
                }
            }
        }
        else
        {
            if (packet_count <= 1.56)
            {
                if (interarrival_time <= 2.39)
                {
                    if (packet_size <= -0.37)
                    {
                        if (packet_count <= 0.21)
                        {
                            return 1;
                        }
                        else
                        {
                            return 1;
                        }
                    }
                    else
                    {
                        return 3;
                    }
                }
                else
                {
                    return 3;
                }
            }
            else
            {
                return 0;
            }
        }
    }
    else
    {
        if (packet_count <= -1.60)
        {
            return 6;
        }
        else
        {
            return 6;
        }
    }
}

// Function to get the majority class
int majority_vote(vector<int> &predictions)
{
    unordered_map<int, int> frequency; // Map to count occurrences of each class
    int max_count = 0, majority_class = -1;

    for (int pred : predictions)
    {
        frequency[pred]++;
        if (frequency[pred] > max_count)
        {
            max_count = frequency[pred];
            majority_class = pred;
        }
    }

    return majority_class;
}

void setup()
{
    Serial.begin(SERIAL_BAUD);
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED)
    {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nWiFi connected");

    WiFi.mode(WIFI_STA);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
}

void loop()
{
    // Nothing needed here – sniffer runs via interrupt
}