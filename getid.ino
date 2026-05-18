#include <Arduino.h>
#include <WiFi.h>

static const char* DEVICE_PREFIX = "ESP32-SB-";

uint64_t chipIdRaw() {
  return ESP.getEfuseMac();
}

String chipIdHex() {
  uint64_t raw = chipIdRaw();
  char buf[17];
  snprintf(buf, sizeof(buf), "%04X%08X", (uint16_t)(raw >> 32), (uint32_t)raw);
  return String(buf);
}

String deviceId() {
  return String(DEVICE_PREFIX) + chipIdHex();
}

void setup() {
  Serial.begin(115200);
  delay(1500);

  Serial.println();
  Serial.println("=== ESP32 Device ID Reader ===");
  Serial.print("eFuse MAC raw: 0x");
  Serial.println((uint64_t)ESP.getEfuseMac(), HEX);

  Serial.print("WiFi MAC: ");
  Serial.println(WiFi.macAddress());

  Serial.print("Provisioning Device ID: ");
  Serial.println(deviceId());

  Serial.println();
  Serial.println("Copy the Provisioning Device ID into the OTA dashboard Provisioning tab.");
}

void loop() {
  delay(5000);
  Serial.print("Provisioning Device ID: ");
  Serial.println(deviceId());
}
