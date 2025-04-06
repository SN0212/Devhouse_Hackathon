#include <WiFi.h>
#include <WiFiClient.h>
#include <vector>
#include <map>
#include <Arduino.h>
#include <math.h>

#define NORMAL_REQUEST_SIZE 1024
#define MAX_PATTERNS_TO_STORE 20
#define MIN_ENTROPY_THRESHOLD 7.5
#define UNUSUAL_CHAR_RATIO 0.35
#define PATTERN_TTL_MS 86400000 // 24 hours

WiFiServer server(80);

// Track stats
int total_passed = 0;
int total_failed = 0;

struct AttackPattern {
  String signature;
  int severity;
  unsigned long lastSeen;
};

std::vector<AttackPattern> learnedPatterns;

struct ClientBehavior {
  float requestIntervalMean;
  float requestIntervalStdDev;
  int requestCount;
  unsigned long lastRequestTime;
};

std::map<String, ClientBehavior> clientBehaviors;

class AnomalyDetector {
private:
  float movingAvg = 0;
  float movingStdDev = 0;
  float alpha = 0.1;

public:
  bool checkAnomaly(float currentValue) {
    float diff = currentValue - movingAvg;
    movingAvg += alpha * diff;
    movingStdDev = alpha * abs(diff) + (1 - alpha) * movingStdDev;
    float threshold = max(3 * movingStdDev, 10.0f);
    return abs(diff) > threshold;
  }
};

AnomalyDetector rateDetector, sizeDetector;
unsigned long lastCleanupTime = 0;

// Utility: Calculate entropy of payload
float calculateEntropy(const uint8_t* data, size_t length) {
  if (length == 0) return 0.0;
  int freq[256] = {0};
  for (size_t i = 0; i < length; i++) freq[data[i]]++;
  float entropy = 0.0;
  for (int i = 0; i < 256; i++) {
    if (freq[i]) {
      float p = (float)freq[i] / length;
      entropy -= p * log2(p);
    }
  }
  return entropy;
}

// Unusual character ratio
float unusualCharRatio(const uint8_t* data, size_t length) {
  int count = 0;
  for (size_t i = 0; i < length; i++) {
    if (data[i] < 32 || data[i] > 126) count++;
  }
  return (float)count / length;
}

// Generate hash-like signature
String generateMinHash(const uint8_t* data, size_t length) {
  uint16_t h1 = 0, h2 = 0;
  for (size_t i = 0; i < length; i++) {
    h1 = (h1 << 5) - h1 + data[i];
    h2 = (h2 << 3) + data[i];
  }
  return String(h1, HEX) + String(h2, HEX);
}

// Known dangerous patterns
bool detectKnownPatterns(const uint8_t* payload, size_t length) {
  const char* patterns[] = {
    "DROP", "DELETE", "UNION", "eval(", "../", "\\x", ";", "|", "&&"
  };

  for (auto p : patterns) {
    if (memmem(payload, length, p, strlen(p))) return true;
  }

  String sig = generateMinHash(payload, length);
  for (auto& pat : learnedPatterns) {
    if (sig.substring(0, 6) == pat.signature.substring(0, 6)) {
      pat.lastSeen = millis();
      pat.severity++;
      return true;
    }
  }
  return false;
}

// Main scoring function
int evaluateRisk(const uint8_t* payload, size_t length, String ip) {
  int risk = 0;

  if (detectKnownPatterns(payload, length)) risk += 40;
  if (calculateEntropy(payload, length) > MIN_ENTROPY_THRESHOLD) risk += 20;
  if (unusualCharRatio(payload, length) > UNUSUAL_CHAR_RATIO) risk += 15;

  unsigned long now = millis();
  unsigned long interval = now - clientBehaviors[ip].lastRequestTime;
  float rate = 1.0 / max((interval / 1000.0), 0.1);

  if (rateDetector.checkAnomaly(rate)) risk += 15;
  if (sizeDetector.checkAnomaly(length)) risk += 10;

  return min(risk, 100);
}

// Pattern learning
void learnPattern(const uint8_t* payload, size_t length) {
  String sig = generateMinHash(payload, length);
  for (auto& p : learnedPatterns) {
    if (sig == p.signature) {
      p.severity++;
      p.lastSeen = millis();
      return;
    }
  }
  if (learnedPatterns.size() >= MAX_PATTERNS_TO_STORE) {
    int oldest = 0;
    for (int i = 1; i < learnedPatterns.size(); i++) {
      if (learnedPatterns[i].lastSeen < learnedPatterns[oldest].lastSeen)
        oldest = i;
    }
    learnedPatterns[oldest] = {sig, 1, millis()};
  } else {
    learnedPatterns.push_back({sig, 1, millis()});
  }
}

// Handle attack or allow
void handleDecision(WiFiClient client, int risk, String ip, const uint8_t* payload, size_t length) {
  if (risk > 70) {
    Serial.println("🚨 BLOCKED " + ip + " | Risk: " + String(risk));
    total_failed++;
    learnPattern(payload, length);
    client.stop();
  } else {
    Serial.println("✅ ALLOWED " + ip + " | Risk: " + String(risk));
    total_passed++;
    client.print("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, legit client!\n");
    client.stop();
  }

  Serial.println("📊 Passed: " + String(total_passed) + " | Failed: " + String(total_failed));
}

// Process each client
void firewallProcess(WiFiClient client) {
  String ip = client.remoteIP().toString();
  unsigned long now = millis();

  if (!clientBehaviors.count(ip)) {
    clientBehaviors[ip] = {0, 0, 0, now};
  }

  unsigned long interval = now - clientBehaviors[ip].lastRequestTime;
  clientBehaviors[ip].lastRequestTime = now;
  clientBehaviors[ip].requestCount++;

  uint8_t buffer[NORMAL_REQUEST_SIZE + 1];
  size_t len = client.readBytes(buffer, NORMAL_REQUEST_SIZE);
  buffer[len] = '\0';

  int risk = evaluateRisk(buffer, len, ip);
  handleDecision(client, risk, ip, buffer, len);
}

// Cleanup expired patterns
void cleanupPatterns() {
  for (int i = learnedPatterns.size() - 1; i >= 0; i--) {
    if (millis() - learnedPatterns[i].lastSeen > PATTERN_TTL_MS) {
      learnedPatterns.erase(learnedPatterns.begin() + i);
    }
  }
}

void setup() {
  Serial.begin(115200);
  WiFi.begin("IoT", "12345678"); // Change to your WiFi creds
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\n✅ Connected to WiFi: " + WiFi.localIP().toString());
  server.begin();

  // Warm up anomaly detectors
  rateDetector.checkAnomaly(1);
  sizeDetector.checkAnomaly(500);
}

void loop() {
  WiFiClient client = server.available();
  if (client) {
    firewallProcess(client);
  }

  if (millis() - lastCleanupTime > 3600000) {
    cleanupPatterns();
    lastCleanupTime = millis();
  }
}
