#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <TensorFlowLite.h>  
#include "tensorflow/lite/micro/micro_interpreter.h"
#include "tensorflow/lite/schema/schema_generated.h"
#include "tensorflow/lite/version.h"
#include "tensorflow/lite/micro/micro_error_reporter.h"
#include "tensorflow/lite/micro/micro_mutable_op_resolver.h"
#include "tensorflow/lite/micro/micro_allocator.h"
#include "tensorflow/lite/micro/system_setup.h"
#include "tensorflow/lite/micro/all_ops_resolver.h"
#include "esp32_attack_model_optimized.h"  // Your trained model binary

#define SERIAL_BAUD 115200
const char *ssid = "IoT";  
const char *password = "12345678";

volatile uint32_t lastTimestamp = 0;
volatile uint32_t packetCount = 0;

// TensorFlow Lite Variables
tflite::MicroErrorReporter micro_error_reporter;
tflite::AllOpsResolver resolver;
const tflite::Model* model = nullptr;
tflite::MicroInterpreter* interpreter = nullptr;
constexpr int tensor_arena_size = 10 * 1024;
uint8_t tensor_arena[tensor_arena_size];

void snifferCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *data = pkt->payload;
    uint16_t packetSize = pkt->rx_ctrl.sig_len;

    uint32_t timestamp = micros();
    uint32_t interarrivalTime = (lastTimestamp == 0) ? 0 : (timestamp - lastTimestamp);
    lastTimestamp = timestamp;

    packetCount++;

    if (packetSize < 34) return;

    uint8_t protocol = data[23];  
    uint8_t ttl = data[22];       
    uint16_t totalLength = (data[16] << 8) | data[17];  
    uint16_t headerLength = (data[14] & 0x0F) * 4;  
    uint16_t payloadSize = totalLength - headerLength;

    char sourceIP[16], destIP[16];
    sprintf(sourceIP, "%d.%d.%d.%d", data[26], data[27], data[28], data[29]);
    sprintf(destIP, "%d.%d.%d.%d", data[30], data[31], data[32], data[33]);

    uint16_t srcPort = 0, destPort = 0, tcpFlags = 0;
    if (protocol == 6 || protocol == 17) {  
        srcPort = (data[headerLength + 14] << 8) | data[headerLength + 15];
        destPort = (data[headerLength + 16] << 8) | data[headerLength + 17];
    }
    if (protocol == 6) {  
        tcpFlags = data[headerLength + 13];  
    }

    // Prepare input data for inference
    float input_data[] = { protocol, srcPort, destPort, packetSize, ttl, tcpFlags, payloadSize, 
                           (float)interarrivalTime, (float)packetCount };

    // Run inference
    TfLiteTensor* input_tensor = interpreter->input(0);
    memcpy(input_tensor->data.f, input_data, sizeof(input_data));

    TfLiteStatus invoke_status = interpreter->Invoke();
    if (invoke_status != kTfLiteOk) {
        Serial.println("Inference failed!");
        return;
    }

    TfLiteTensor* output_tensor = interpreter->output(0);
    float* output_data = output_tensor->data.f;

    // Find class with highest probability
    int predicted_class = 0;
    float max_prob = output_data[0];
    for (int i = 1; i < 3; i++) {
        if (output_data[i] > max_prob) {
            max_prob = output_data[i];
            predicted_class = i;
        }
    }

    // Send output via Serial
    Serial.printf("%lu,%s,%s,%d,%d,%d,%d,%d,%d,%d,%lu,%lu,Predicted Class: %d\n", 
            timestamp, sourceIP, destIP, protocol, srcPort, destPort, 
            packetSize, ttl, tcpFlags, payloadSize, interarrivalTime, packetCount, predicted_class);
}

void setup() {
    Serial.begin(SERIAL_BAUD);
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nWiFi connected");

    WiFi.mode(WIFI_STA);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);

    // Load TensorFlow Lite model
    model = tflite::GetModel(esp32_attack_model_optimized);
    if (model->version() != TFLITE_SCHEMA_VERSION) {
        Serial.println("Model schema version mismatch!");
        return;
    }

    // Initialize the TFLite Interpreter
    interpreter = new tflite::MicroInterpreter(model, resolver, tensor_arena, tensor_arena_size, &micro_error_reporter);
    interpreter->AllocateTensors();
}

void loop() {
    // ESP32 packet sniffing runs in the background via snifferCallback
}
