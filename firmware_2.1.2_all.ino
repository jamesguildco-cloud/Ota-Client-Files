#include <Arduino.h>
#include <WiFi.h>
#include <Wire.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <ArduinoJson.h>
#include <LiquidCrystal_I2C.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#include "mbedtls/base64.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_csr.h"

/*
  ESP32 OTA Client for the GuildCo OTA backend

  Secure model:
  - device generates its private key locally
  - device generates its CSR locally
  - server signs CSR and returns only the certificate
  - device stores cert/key in LittleFS

  Flow:
  1. Wi-Fi connect
  2. Zero-touch bootstrap via POST /provisioning/bootstrap
  3. mTLS register via POST /device/register
  4. Poll GET /device/next
  5. Download image into inactive OTA partition
  6. Verify SHA-256 and detached KMS signature
  7. Report /device/progress and /device/health
  8. Reboot into new image

  Display auto-detection:
  - At boot the firmware scans the I2C bus.
  - OLED (SSD1306) is expected at 0x3C or 0x3D.
  - LCD (PCF8574 backpack) is expected at 0x27 or 0x3F.
  - Whichever responds first is used; the other library is left idle.
  - If neither is found, status is sent to Serial only.
*/

// ---------------------------------------------------------------------------
// Fleet defaults + network config
// ---------------------------------------------------------------------------
// These are defaults only. Values that vary per device are stored in Preferences
// and survive OTA updates. Do not hardcode a unique DEVICE_ID in OTA binaries.
static const char* DEFAULT_WIFI_SSID = "Gonah_5G"; //change the wifi name
static const char* DEFAULT_WIFI_PASSWORD = "thinthin8"; //change the password
static const char* DEFAULT_DEVICE_PREFIX = "ESP32-SB-"; 
static const char* DEFAULT_SERVER_URL = "https://serversb.theguildco.com";
static const char* DEFAULT_EXPECTED_DOWNLOAD_HOST = "ota-firware-bucket3.s3.ap-south-1.amazonaws.com";
static const char* DEFAULT_CHANNEL = "stable"; //edit the channel if using other than stable
static const char* APP_VERSION = "1.0.0";

// Test-only override. Leave empty for production/fleet firmware.
// When set, this value is used as the device_id and saved in Preferences.
static const char* TEST_DEVICE_ID_OVERRIDE = "";

// ---------------------------------------------------------------------------
// Display configuration
// ---------------------------------------------------------------------------
// LCD (PCF8574 I2C backpack) — common addresses: 0x27, 0x3F
static const uint8_t LCD_COLUMNS    = 16;
static const uint8_t LCD_ROWS       = 2;
static const uint8_t LCD_ADDR_1     = 0x27;
static const uint8_t LCD_ADDR_2     = 0x3F;

// OLED (SSD1306) — common addresses: 0x3C, 0x3D
static const uint8_t OLED_ADDR_1    = 0x3C;
static const uint8_t OLED_ADDR_2    = 0x3D;
static const uint8_t OLED_WIDTH     = 128;
static const uint8_t OLED_HEIGHT    =  64;

// Which display type was detected at boot
enum DisplayType { DISPLAY_NONE, DISPLAY_LCD, DISPLAY_OLED };
static DisplayType activeDisplay    = DISPLAY_NONE;
static uint8_t     detectedAddr     = 0x00;

// Root CA for your control-plane endpoint (bootstrap/register/next/progress/health).
// Replace with the CA chain that signs https://server.theguildco.com
static const char* SERVER_ROOT_CA_PEM = R"PEM(
-----BEGIN CERTIFICATE-----
MIIFBTCCAu2gAwIBAgIQWgDyEtjUtIDzkkFX6imDBTANBgkqhkiG9w0BAQsFADBP
MQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFy
Y2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTAeFw0yNDAzMTMwMDAwMDBa
Fw0yNzAzMTIyMzU5NTlaMDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBF
bmNyeXB0MQwwCgYDVQQDEwNSMTMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQClZ3CN0FaBZBUXYc25BtStGZCMJlA3mBZjklTb2cyEBZPs0+wIG6BgUUNI
fSvHSJaetC3ancgnO1ehn6vw1g7UDjDKb5ux0daknTI+WE41b0VYaHEX/D7YXYKg
L7JRbLAaXbhZzjVlyIuhrxA3/+OcXcJJFzT/jCuLjfC8cSyTDB0FxLrHzarJXnzR
yQH3nAP2/Apd9Np75tt2QnDr9E0i2gB3b9bJXxf92nUupVcM9upctuBzpWjPoXTi
dYJ+EJ/B9aLrAek4sQpEzNPCifVJNYIKNLMc6YjCR06CDgo28EdPivEpBHXazeGa
XP9enZiVuppD0EqiFwUBBDDTMrOPAgMBAAGjgfgwgfUwDgYDVR0PAQH/BAQDAgGG
MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATASBgNVHRMBAf8ECDAGAQH/
AgEAMB0GA1UdDgQWBBTnq58PLDOgU9NeT3jIsoQOO9aSMzAfBgNVHSMEGDAWgBR5
tFnme7bl5AFzgAiIyBpY9umbbjAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAKG
Fmh0dHA6Ly94MS5pLmxlbmNyLm9yZy8wEwYDVR0gBAwwCjAIBgZngQwBAgEwJwYD
VR0fBCAwHjAcoBqgGIYWaHR0cDovL3gxLmMubGVuY3Iub3JnLzANBgkqhkiG9w0B
AQsFAAOCAgEAUTdYUqEimzW7TbrOypLqCfL7VOwYf/Q79OH5cHLCZeggfQhDconl
k7Kgh8b0vi+/XuWu7CN8n/UPeg1vo3G+taXirrytthQinAHGwc/UdbOygJa9zuBc
VyqoH3CXTXDInT+8a+c3aEVMJ2St+pSn4ed+WkDp8ijsijvEyFwE47hulW0Ltzjg
9fOV5Pmrg/zxWbRuL+k0DBDHEJennCsAen7c35Pmx7jpmJ/HtgRhcnz0yjSBvyIw
6L1QIupkCv2SBODT/xDD3gfQQyKv6roV4G2EhfEyAsWpmojxjCUCGiyg97FvDtm/
NK2LSc9lybKxB73I2+P2G3CaWpvvpAiHCVu30jW8GCxKdfhsXtnIy2imskQqVZ2m
0Pmxobb28Tucr7xBK7CtwvPrb79os7u2XP3O5f9b/H66GNyRrglRXlrYjI1oGYL/
f4I1n/Sgusda6WvA6C190kxjU15Y12mHU4+BxyR9cx2hhGS9fAjMZKJss28qxvz6
Axu4CaDmRNZpK/pQrXF17yXCXkmEWgvSOEZy6Z9pcbLIVEGckV/iVeq0AOo2pkg9
p4QRIy0tK2diRENLSF2KysFwbY6B26BFeFs3v1sYVRhFW9nLkOrQVporCS0KyZmf
wVD89qSTlnctLcZnIavjKsKUu1nA1iU0yYMdYepKR7lWbnwhdx3ewok=
-----END CERTIFICATE-----
)PEM";

// Root CA for presigned firmware downloads.
// This is intentionally separate from SERVER_ROOT_CA_PEM because S3 / CDN hosts
// often use a different public CA chain than the control plane.
static const char* DOWNLOAD_ROOT_CA_PEM = R"PEM(
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgITBn+USionzfP6wq4rAfkI7rnExjANBgkqhkiG9w0BAQsF
ADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj
b3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4x
OzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAtIEcyMB4XDTE1MDUyNTEyMDAwMFoXDTM3MTIzMTAxMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
jgSubJrIqg0CAwEAAaOCATEwggEtMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/
BAQDAgGGMB0GA1UdDgQWBBSEGMyFNOy8DJSULghZnMeyEE4KCDAfBgNVHSMEGDAW
gBScXwDfqgHXMCs4iKK4bUqc8hGRgzB4BggrBgEFBQcBAQRsMGowLgYIKwYBBQUH
MAGGImh0dHA6Ly9vY3NwLnJvb3RnMi5hbWF6b250cnVzdC5jb20wOAYIKwYBBQUH
MAKGLGh0dHA6Ly9jcnQucm9vdGcyLmFtYXpvbnRydXN0LmNvbS9yb290ZzIuY2Vy
MD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jcmwucm9vdGcyLmFtYXpvbnRydXN0
LmNvbS9yb290ZzIuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQsF
AAOCAQEAYjdCXLwQtT6LLOkMm2xF4gcAevnFWAu5CIw+7bMlPLVvUOTNNWqnkzSW
MiGpSESrnO09tKpzbeR/FoCJbM8oAxiDR3mjEH4wW6w7sGDgd9QIpuEdfF7Au/ma
eyKdpwAJfqxGF4PcnCZXmTA5YpaP7dreqsXMGz7KQ2hsVxa81Q4gLv7/wmpdLqBK
bRRYh5TmOTFffHPLkIhqhBGWJ6bt2YFGpn6jcgAKUj6DiAdjd4lpFw85hdKrCEVN
0FE6/V1dN2RMfjCyVSRCnTawXZwXgWHxyvkQAiSr6w10kY17RSlQOYiypok1JR4U
akcjMS9cmvqtmg5iUaQqqcT5NJ0hGA==
-----END CERTIFICATE-----
)PEM";

// For production keep this false and provide DOWNLOAD_ROOT_CA_PEM above.
static const bool DOWNLOAD_TLS_INSECURE = false;

static const char* FS_KEY_PATH = "/device.key.pem";
static const char* FS_CERT_PATH = "/device.cert.pem";
static const char* FS_CSR_PATH = "/device.csr.pem";

static const uint32_t WIFI_TIMEOUT_MS = 30000;
static const uint32_t POLL_INTERVAL_MS = 5UL * 60UL * 1000UL;
static const uint32_t STATUS_INTERVAL_MS = 5000;

Preferences prefs;
String clientKeyPem;
String clientCertPem;
String cachedSigningKeyPem;

// Both display objects are declared; only the detected one is initialised.
LiquidCrystal_I2C lcd(LCD_ADDR_1, LCD_COLUMNS, LCD_ROWS);   // addr updated at runtime if needed
Adafruit_SSD1306  oled(OLED_WIDTH, OLED_HEIGHT, &Wire, -1);

struct FirmwareOffer {
  String firmwareId;
  String version;
  String channel;
  String url;
  String checksumSha256;
  String signatureB64;
  String format;
  size_t sizeBytes = 0;
  bool valid = false;
};

// ---------------------------------------------------------------------------
// Display auto-detection
// ---------------------------------------------------------------------------

// Returns true when a device ACKs at the given I2C address.
bool i2cProbe(uint8_t addr) {
  Wire.beginTransmission(addr);
  return Wire.endTransmission() == 0;
}

// Scans for known LCD and OLED addresses.
// OLED is checked first; change the order below to prefer LCD instead.
DisplayType detectAndInitDisplay() {
  // --- probe OLED addresses ---
  if (i2cProbe(OLED_ADDR_1) || i2cProbe(OLED_ADDR_2)) {
    detectedAddr = i2cProbe(OLED_ADDR_1) ? OLED_ADDR_1 : OLED_ADDR_2;
    if (oled.begin(SSD1306_SWITCHCAPVCC, detectedAddr)) {
      oled.clearDisplay();
      oled.setTextColor(SSD1306_WHITE);
      oled.display();
      Serial.printf("OLED detected at 0x%02X\n", detectedAddr);
      return DISPLAY_OLED;
    }
  }

  // --- probe LCD addresses ---
  if (i2cProbe(LCD_ADDR_1) || i2cProbe(LCD_ADDR_2)) {
    detectedAddr = i2cProbe(LCD_ADDR_1) ? LCD_ADDR_1 : LCD_ADDR_2;
    // Reinitialise the lcd object with the actual address found
    lcd = LiquidCrystal_I2C(detectedAddr, LCD_COLUMNS, LCD_ROWS);
    lcd.init();
    lcd.backlight();
    Serial.printf("LCD detected at 0x%02X\n", detectedAddr);
    return DISPLAY_LCD;
  }

  Serial.println("No display detected on I2C bus — output via Serial only.");
  return DISPLAY_NONE;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
String prefsGetString(const char* key, const String& fallback = "") {
  String v = prefs.getString(key, fallback);
  return v.length() ? v : fallback;
}

void prefsSetString(const char* key, const String& value) {
  prefs.putString(key, value);
}

bool prefsGetBool(const char* key, bool fallback = false) {
  return prefs.getBool(key, fallback);
}

void prefsSetBool(const char* key, bool value) {
  prefs.putBool(key, value);
}

void logLine(const String& msg) {
  Serial.println(msg);
}

// Unified display function — dispatches to whichever screen was detected.
// Signature and all call sites are identical to the original lcdShow().
void lcdShow(const String& line1, const String& line2 = "") {
  if (activeDisplay == DISPLAY_LCD) {
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print(line1.substring(0, LCD_COLUMNS));
    if (LCD_ROWS > 1) {
      lcd.setCursor(0, 1);
      lcd.print(line2.substring(0, LCD_COLUMNS));
    }

  } else if (activeDisplay == DISPLAY_OLED) {
    oled.clearDisplay();
    oled.setTextSize(1);
    oled.setTextColor(SSD1306_WHITE);
    oled.setCursor(0, 0);
    oled.print(line1);
    if (line2.length()) {
      oled.setCursor(0, 32);
      oled.print(line2);
    }
    oled.display();

  }
  // DISPLAY_NONE: status already printed via logLine / Serial
}

bool writeFile(const char* path, const String& data) {
  File f = LittleFS.open(path, "w");
  if (!f) return false;
  size_t written = f.print(data);
  f.close();
  return written == data.length();
}

String readFile(const char* path) {
  File f = LittleFS.open(path, "r");
  if (!f) return "";
  String out = f.readString();
  f.close();
  return out;
}

bool fileExists(const char* path) {
  return LittleFS.exists(path);
}

String getTenantId() {
  return prefsGetString("tenant_id", "");
}

String getChannel() {
  return prefsGetString("channel", DEFAULT_CHANNEL);
}

String getServerUrl() {
  return prefsGetString("server_url", DEFAULT_SERVER_URL);
}

String getExpectedDownloadHost() {
  return prefsGetString("download_host", DEFAULT_EXPECTED_DOWNLOAD_HOST);
}

String getWifiSsid() {
  return prefsGetString("wifi_ssid", DEFAULT_WIFI_SSID);
}

String getWifiPassword() {
  return prefsGetString("wifi_password", DEFAULT_WIFI_PASSWORD);
}

void seedDefaultConfigIfMissing() {
  if (!prefsGetString("wifi_ssid", "").length()) {
    prefsSetString("wifi_ssid", DEFAULT_WIFI_SSID);
  }
  if (!prefsGetString("wifi_password", "").length()) {
    prefsSetString("wifi_password", DEFAULT_WIFI_PASSWORD);
  }
  if (!prefsGetString("server_url", "").length()) {
    prefsSetString("server_url", DEFAULT_SERVER_URL);
  }
  if (!prefsGetString("download_host", "").length()) {
    prefsSetString("download_host", DEFAULT_EXPECTED_DOWNLOAD_HOST);
  }
  if (!prefsGetString("channel", "").length()) {
    prefsSetString("channel", DEFAULT_CHANNEL);
  }
}

String getDeviceId() {
  String saved = prefsGetString("device_id", "");
  if (saved.length()) return saved;

  String testOverride = String(TEST_DEVICE_ID_OVERRIDE);
  testOverride.trim();
  if (testOverride.length()) {
    prefsSetString("device_id", testOverride);
    return testOverride;
  }

  // Stable factory fallback: ESP.getEfuseMac() is the ESP32's factory-programmed
  // unique hardware MAC/eFuse identifier. This avoids baking per-device IDs into
  // OTA binaries while still giving each physical board a stable identity.
  String factoryId = String(DEFAULT_DEVICE_PREFIX) + chipIdHex();
  prefsSetString("device_id", factoryId);
  return factoryId;
}

String getCurrentVersion() {
  return prefsGetString("current_version", "");
}

void setCurrentVersion(const String& version) {
  prefsSetString("current_version", version);
}

uint64_t chipIdRaw() {
  uint64_t chipid = ESP.getEfuseMac();
  return chipid;
}

String chipIdHex() {
  uint64_t raw = chipIdRaw();
  char buf[17];
  snprintf(buf, sizeof(buf), "%04X%08X", (uint16_t)(raw >> 32), (uint32_t)raw);
  return String(buf);
}

String sha256Hex(const uint8_t* data, size_t len) {
  uint8_t out[32];
  mbedtls_sha256(data, len, out, 0);
  char hex[65];
  for (int i = 0; i < 32; i++) {
    sprintf(hex + (i * 2), "%02x", out[i]);
  }
  hex[64] = '\0';
  return String(hex);
}

String sha256HexString(const String& value) {
  return sha256Hex(reinterpret_cast<const uint8_t*>(value.c_str()), value.length());
}

String deviceFingerprint() {
  String material = getDeviceId() + "|esp32|" + chipIdHex();
  return sha256HexString(material);
}

void connectWiFi() {
  String ssid = getWifiSsid();
  String password = getWifiPassword();

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid.c_str(), password.c_str());
  logLine("Connecting Wi-Fi...");
  lcdShow("WiFi connect", getDeviceId());
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
    if (millis() - start > WIFI_TIMEOUT_MS) {
      logLine("\nWi-Fi timeout");
      ESP.restart();
    }
  }
  logLine("\nWi-Fi connected: " + WiFi.localIP().toString());
  prefsSetString("wifi_ssid", ssid);
  prefsSetString("wifi_password", password);
  lcdShow("WiFi connected", WiFi.localIP().toString());
}

void configureServerTlsClient(WiFiClientSecure& client, bool useMutualTls) {
  client.setTimeout(30000);
  client.setCACert(SERVER_ROOT_CA_PEM);
  if (useMutualTls && clientCertPem.length() && clientKeyPem.length()) {
    client.setCertificate(clientCertPem.c_str());
    client.setPrivateKey(clientKeyPem.c_str());
  }
}

void configureDownloadTlsClient(WiFiClientSecure& client) {
  client.setTimeout(60000);
  if (DOWNLOAD_TLS_INSECURE) {
    client.setInsecure();
  } else {
    client.setCACert(DOWNLOAD_ROOT_CA_PEM);
  }
}

bool beginJsonRequest(HTTPClient& http, WiFiClientSecure& client, const String& url) {
  if (!http.begin(client, url)) {
    logLine("HTTP begin failed: " + url);
    return false;
  }
  http.addHeader("Content-Type", "application/json");
  String tenantId = getTenantId();
  if (tenantId.length()) {
    http.addHeader("x-tenant-id", tenantId);
  }
  return true;
}

bool beginMtlSJsonRequest(HTTPClient& http, WiFiClientSecure& client, const String& url) {
  configureServerTlsClient(client, true);
  return beginJsonRequest(http, client, url);
}

// ---------------------------------------------------------------------------
// Key + CSR generation
// ---------------------------------------------------------------------------
bool generateKeyAndCsr() {
  mbedtls_pk_context key;
  mbedtls_x509write_csr req;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctrDrbg;
  String subject = "CN=" + getDeviceId() + ",O=GuildCo OTA";
  unsigned char* keyPem = nullptr;
  unsigned char* csrPem = nullptr;
  bool ok = false;

  mbedtls_pk_init(&key);
  mbedtls_x509write_csr_init(&req);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctrDrbg);

  const char* pers = "guildco-esp32-ota";
  int rc = mbedtls_ctr_drbg_seed(
    &ctrDrbg,
    mbedtls_entropy_func,
    &entropy,
    reinterpret_cast<const unsigned char*>(pers),
    strlen(pers)
  );
  if (rc != 0) {
    logLine("mbedtls_ctr_drbg_seed failed");
    goto cleanup_fail;
  }

  rc = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  if (rc != 0) {
    logLine("mbedtls_pk_setup failed");
    goto cleanup_fail;
  }

  rc = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctrDrbg, 2048, 65537);
  if (rc != 0) {
    logLine("mbedtls_rsa_gen_key failed");
    goto cleanup_fail;
  }

  keyPem = static_cast<unsigned char*>(calloc(1, 4096));
  csrPem = static_cast<unsigned char*>(calloc(1, 4096));
  if (!keyPem || !csrPem) {
    logLine("calloc failed for key/csr buffers");
    goto cleanup_fail;
  }

  rc = mbedtls_pk_write_key_pem(&key, keyPem, 4096);
  if (rc != 0) {
    logLine("mbedtls_pk_write_key_pem failed");
    goto cleanup_fail;
  }

  mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
  mbedtls_x509write_csr_set_key(&req, &key);
  rc = mbedtls_x509write_csr_set_subject_name(&req, subject.c_str());
  if (rc != 0) {
    logLine("mbedtls_x509write_csr_set_subject_name failed");
    goto cleanup_fail;
  }

  rc = mbedtls_x509write_csr_pem(
    &req,
    csrPem,
    4096,
    mbedtls_ctr_drbg_random,
    &ctrDrbg
  );
  if (rc != 0) {
    logLine("mbedtls_x509write_csr_pem failed");
    goto cleanup_fail;
  }

  clientKeyPem = String(reinterpret_cast<char*>(keyPem));
  if (!writeFile(FS_KEY_PATH, clientKeyPem)) {
    logLine("Failed to write key to LittleFS");
    goto cleanup_fail;
  }

  if (!writeFile(FS_CSR_PATH, String(reinterpret_cast<char*>(csrPem)))) {
    logLine("Failed to write CSR to LittleFS");
    goto cleanup_fail;
  }

  ok = true;

cleanup_fail:
  if (keyPem) free(keyPem);
  if (csrPem) free(csrPem);
  mbedtls_x509write_csr_free(&req);
  mbedtls_pk_free(&key);
  mbedtls_ctr_drbg_free(&ctrDrbg);
  mbedtls_entropy_free(&entropy);
  return ok;
}

bool ensureLocalIdentity() {
  if (!fileExists(FS_KEY_PATH) || !fileExists(FS_CSR_PATH)) {
    return generateKeyAndCsr();
  }
  clientKeyPem = readFile(FS_KEY_PATH);
  return clientKeyPem.length() > 0;
}

// ---------------------------------------------------------------------------
// Backend calls
// ---------------------------------------------------------------------------
bool bootstrapIfNeeded(bool force = false) {
  if (!ensureLocalIdentity()) return false;

  if (fileExists(FS_CERT_PATH) && !force) {
    clientCertPem = readFile(FS_CERT_PATH);
    return clientCertPem.length() > 0;
  }

  WiFiClientSecure client;
  configureServerTlsClient(client, false);
  HTTPClient http;
  if (!beginJsonRequest(http, client, getServerUrl() + "/provisioning/bootstrap")) {
    return false;
  }

  DynamicJsonDocument doc(4096);
  doc["device_id"] = getDeviceId();
  doc["fingerprint"] = deviceFingerprint();
  doc["csr"] = readFile(FS_CSR_PATH);

  String body;
  serializeJson(doc, body);
  int code = http.POST(body);
  String response = http.getString();
  http.end();

  if (code != 200) {
    logLine("Bootstrap failed: " + String(code) + " " + response);
    lcdShow("Bootstrap fail", String(code));
    return false;
  }

  DynamicJsonDocument out(4096);
  DeserializationError err = deserializeJson(out, response);
  if (err) {
    logLine("Bootstrap JSON parse failed");
    return false;
  }

  String cert = out["certificate"] | "";
  if (!cert.length()) {
    logLine("Bootstrap response missing certificate");
    lcdShow("Bootstrap fail", "No cert");
    return false;
  }

  clientCertPem = cert;
  if (!writeFile(FS_CERT_PATH, clientCertPem)) {
    logLine("Failed to store certificate");
    return false;
  }

  String tenantId = out["tenant_id"] | "";
  if (tenantId.length()) prefsSetString("tenant_id", tenantId);

  String deviceId = out["device_id"] | "";
  if (deviceId.length()) prefsSetString("device_id", deviceId);

  String channel = out["channel"] | "";
  if (channel.length()) prefsSetString("channel", channel);

  String serverUrl = out["server_url"] | "";
  if (serverUrl.length()) prefsSetString("server_url", serverUrl);

  logLine("Bootstrap OK for tenant " + tenantId);
  lcdShow("Bootstrap OK", tenantId);
  return true;
}

bool registerDevice() {
  if (!clientKeyPem.length()) clientKeyPem = readFile(FS_KEY_PATH);
  if (!clientCertPem.length()) clientCertPem = readFile(FS_CERT_PATH);

  WiFiClientSecure client;
  HTTPClient http;
  if (!beginMtlSJsonRequest(http, client, getServerUrl() + "/device/register")) {
    return false;
  }

  DynamicJsonDocument doc(2048);
  doc["model"] = "ESP32";
  doc["channel"] = getChannel();
  String version = getCurrentVersion();
  if (version.length()) {
    doc["current_version"] = version;
  } else {
    doc["current_version"] = nullptr;
  }
  JsonObject meta = doc.createNestedObject("metadata");
  JsonObject runtime = meta.createNestedObject("runtime");
  runtime["mode"] = "esp32";
  runtime["chip_id"] = chipIdHex();
  runtime["sdk"] = ESP.getSdkVersion();
  runtime["free_heap"] = ESP.getFreeHeap();

  String body;
  serializeJson(doc, body);
  int code = http.POST(body);
  String response = http.getString();
  http.end();

  if (code != 200) {
    logLine("Register failed: " + String(code) + " " + response);
    lcdShow("Register fail", String(code));
    return false;
  }

  logLine("Register OK");
  lcdShow("Register OK", getCurrentVersion().length() ? getCurrentVersion() : APP_VERSION);
  return true;
}

FirmwareOffer pollNext() {
  FirmwareOffer offer;
  if (!clientKeyPem.length()) clientKeyPem = readFile(FS_KEY_PATH);
  if (!clientCertPem.length()) clientCertPem = readFile(FS_CERT_PATH);

  WiFiClientSecure client;
  configureServerTlsClient(client, true);
  HTTPClient http;
  String url = getServerUrl() + "/device/next?channel=" + getChannel();
  if (!http.begin(client, url)) {
    logLine("Poll begin failed");
    return offer;
  }

  String tenantId = getTenantId();
  if (tenantId.length()) http.addHeader("x-tenant-id", tenantId);

  int code = http.GET();
  if (code == 204) {
    http.end();
    return offer;
  }

  String response = http.getString();
  http.end();
  if (code != 200) {
    logLine("Poll failed: " + String(code) + " " + response);
    lcdShow("Poll fail", String(code));
    return offer;
  }

  DynamicJsonDocument doc(4096);
  DeserializationError err = deserializeJson(doc, response);
  if (err) {
    logLine("Poll JSON parse failed");
    return offer;
  }

  offer.firmwareId = doc["firmware_id"] | "";
  offer.version = doc["version"] | "";
  offer.channel = doc["channel"] | "";
  offer.url = doc["url"] | "";
  offer.checksumSha256 = doc["checksum_sha256"] | "";
  offer.signatureB64 = doc["signature"] | "";
  offer.format = doc["format"] | "bin";
  offer.sizeBytes = doc["size_bytes"] | doc["size"] | 0;
  offer.valid = offer.firmwareId.length() && offer.url.length() && offer.version.length();
  return offer;
}

bool postProgress(const FirmwareOffer& fw, uint32_t downloaded, uint32_t total, const char* status, const char* lifecycleState = nullptr, const char* errorCode = nullptr) {
  WiFiClientSecure client;
  HTTPClient http;
  if (!beginMtlSJsonRequest(http, client, getServerUrl() + "/device/progress")) {
    return false;
  }

  DynamicJsonDocument doc(1024);
  doc["firmware_id"] = fw.firmwareId;
  doc["percent"] = total > 0 ? (downloaded * 100U) / total : 0U;
  doc["downloaded_bytes"] = downloaded;
  doc["total_bytes"] = total;
  doc["status"] = status;
  doc["version"] = fw.version;
  if (lifecycleState) doc["lifecycle_state"] = lifecycleState;
  if (errorCode) doc["error_code"] = errorCode;

  String body;
  serializeJson(doc, body);
  int code = http.POST(body);
  String response = http.getString();
  http.end();
  if (code != 200) {
    logLine("Progress failed: " + String(code) + " " + response);
    return false;
  }
  return true;
}

bool postHealth(const FirmwareOffer& fw, const char* status, const char* errorMessage = nullptr) {
  WiFiClientSecure client;
  HTTPClient http;
  if (!beginMtlSJsonRequest(http, client, getServerUrl() + "/device/health")) {
    return false;
  }

  DynamicJsonDocument doc(1024);
  doc["status"] = status;
  JsonObject metrics = doc.createNestedObject("metrics");
  metrics["version"] = fw.version;
  metrics["free_heap"] = ESP.getFreeHeap();
  if (errorMessage) doc["error_message"] = errorMessage;

  String body;
  serializeJson(doc, body);
  int code = http.POST(body);
  String response = http.getString();
  http.end();
  if (code != 200) {
    logLine("Health failed: " + String(code) + " " + response);
    return false;
  }
  return true;
}

String fetchSigningKeyPem() {
  if (cachedSigningKeyPem.length()) return cachedSigningKeyPem;

  WiFiClientSecure client;
  configureServerTlsClient(client, false);
  HTTPClient http;
  if (!http.begin(client, getServerUrl() + "/public/firmware-signing-key")) {
    return "";
  }
  String tenantId = getTenantId();
  if (tenantId.length()) http.addHeader("x-tenant-id", tenantId);
  int code = http.GET();
  String pem = http.getString();
  http.end();
  if (code == 200) {
    cachedSigningKeyPem = pem;
  }
  return cachedSigningKeyPem;
}

bool verifyDetachedSignature(const String& digestHex, const String& signatureB64) {
  if (!signatureB64.length()) return true;
  String pem = fetchSigningKeyPem();
  if (!pem.length()) {
    logLine("Signing key fetch failed");
    return false;
  }

  uint8_t digest[32];
  for (int i = 0; i < 32; i++) {
    String byteHex = digestHex.substring(i * 2, i * 2 + 2);
    digest[i] = static_cast<uint8_t>(strtoul(byteHex.c_str(), nullptr, 16));
  }

  size_t sigLen = 0;
  mbedtls_base64_decode(nullptr, 0, &sigLen,
                        reinterpret_cast<const unsigned char*>(signatureB64.c_str()),
                        signatureB64.length());
  std::unique_ptr<unsigned char[]> sig(new unsigned char[sigLen]);
  if (mbedtls_base64_decode(sig.get(), sigLen, &sigLen,
                            reinterpret_cast<const unsigned char*>(signatureB64.c_str()),
                            signatureB64.length()) != 0) {
    logLine("Signature base64 decode failed");
    return false;
  }

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  int rc = mbedtls_pk_parse_public_key(
    &pk,
    reinterpret_cast<const unsigned char*>(pem.c_str()),
    pem.length() + 1
  );
  if (rc != 0) {
    logLine("Public key parse failed");
    mbedtls_pk_free(&pk);
    return false;
  }

  if (mbedtls_pk_get_type(&pk) == MBEDTLS_PK_RSA) {
    mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
  }

  rc = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, digest, sizeof(digest), sig.get(), sigLen);
  mbedtls_pk_free(&pk);
  return rc == 0;
}

bool applyOffer(const FirmwareOffer& fw) {
  WiFiClientSecure client;
  configureDownloadTlsClient(client);
  HTTPClient http;
  if (!http.begin(client, fw.url)) {
    logLine("Download begin failed");
    lcdShow("Download fail", "Begin");
    return false;
  }

  int code = http.GET();
  if (code != 200) {
    logLine("Download failed: " + String(code));
    lcdShow("Download fail", String(code));
    http.end();
    return false;
  }

  int total = http.getSize();
  if (total <= 0 && fw.sizeBytes > 0) {
    total = static_cast<int>(fw.sizeBytes);
  }

  if (!Update.begin(total > 0 ? total : UPDATE_SIZE_UNKNOWN)) {
    logLine("Update.begin failed");
    http.end();
    return false;
  }

  WiFiClient* stream = http.getStreamPtr();
  uint8_t buffer[2048];
  uint32_t writtenTotal = 0;
  uint32_t lastProgressAt = millis();

  mbedtls_sha256_context shaCtx;
  mbedtls_sha256_init(&shaCtx);
  mbedtls_sha256_starts(&shaCtx, 0);

  postProgress(fw, 0, total > 0 ? total : fw.sizeBytes, "in_progress");
  lcdShow("Downloading", fw.version);

  while (http.connected() && (total > 0 ? writtenTotal < (uint32_t)total : true)) {
    size_t available = stream->available();
    if (!available) {
      delay(10);
      continue;
    }

    int readLen = stream->readBytes(buffer, available > sizeof(buffer) ? sizeof(buffer) : available);
    if (readLen <= 0) continue;

    if (Update.write(buffer, readLen) != (size_t)readLen) {
      Update.abort();
      mbedtls_sha256_free(&shaCtx);
      http.end();
      postHealth(fw, "failed", "flash_write_failed");
      lcdShow("OTA fail", "Write");
      return false;
    }

    mbedtls_sha256_update(&shaCtx, buffer, readLen);
    writtenTotal += readLen;

    if (millis() - lastProgressAt > STATUS_INTERVAL_MS) {
      postProgress(fw, writtenTotal, total > 0 ? total : fw.sizeBytes, "in_progress");
      lastProgressAt = millis();
    }
  }

  uint8_t digest[32];
  mbedtls_sha256_finish(&shaCtx, digest);
  mbedtls_sha256_free(&shaCtx);
  http.end();

  char digestHex[65];
  for (int i = 0; i < 32; i++) {
    sprintf(digestHex + (i * 2), "%02x", digest[i]);
  }
  digestHex[64] = '\0';

  postProgress(fw, writtenTotal, total > 0 ? total : fw.sizeBytes, "completed", "verifying");

  if (fw.checksumSha256.length() && !fw.checksumSha256.equalsIgnoreCase(String(digestHex))) {
    logLine("Checksum mismatch");
    Update.abort();
    postHealth(fw, "failed", "checksum_mismatch");
    lcdShow("OTA fail", "Checksum");
    return false;
  }

  if (fw.signatureB64.length() && !verifyDetachedSignature(String(digestHex), fw.signatureB64)) {
    logLine("Signature verification failed");
    Update.abort();
    postHealth(fw, "failed", "signature_verify_failed");
    lcdShow("OTA fail", "Signature");
    return false;
  }

  postProgress(fw, writtenTotal, total > 0 ? total : fw.sizeBytes, "completed", "installing");
  lcdShow("Installing", fw.version);

  if (!Update.end()) {
    logLine("Update.end failed");
    postHealth(fw, "failed", "update_end_failed");
    lcdShow("OTA fail", "Update.end");
    return false;
  }

  if (!Update.isFinished()) {
    logLine("Update not finished");
    postHealth(fw, "failed", "update_incomplete");
    lcdShow("OTA fail", "Incomplete");
    return false;
  }

  setCurrentVersion(fw.version);
  postProgress(fw, writtenTotal, total > 0 ? total : fw.sizeBytes, "completed", "rebooting");
  postHealth(fw, "success");

  logLine("OTA applied for version " + fw.version + ", rebooting...");
  lcdShow("OTA OK", fw.version);
  delay(2000);
  ESP.restart();
  return true;
}

void runOtaCycle() {
  if (!bootstrapIfNeeded(false)) {
    logLine("Bootstrap not complete");
    return;
  }
  if (!registerDevice()) {
    logLine("Register failed");
    return;
  }

  FirmwareOffer fw = pollNext();
  if (!fw.valid) {
    logLine("No update available");
    lcdShow("Version", getCurrentVersion().length() ? getCurrentVersion() : APP_VERSION);
    return;
  }

  logLine("Update available: " + fw.version);
  lcdShow("Update avail", fw.version);
  if (!applyOffer(fw)) {
    logLine("OTA apply failed");
  }
}

// ---------------------------------------------------------------------------
// Arduino entrypoints
// ---------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(1000);

  if (!LittleFS.begin(true)) {
    logLine("LittleFS mount failed");
    return;
  }

  prefs.begin("ota", false);
  seedDefaultConfigIfMissing();

  // I2C bus must be up before the display scan
  Wire.begin();
  activeDisplay = detectAndInitDisplay();

  lcdShow("Booting", APP_VERSION);
  connectWiFi();

  clientKeyPem = readFile(FS_KEY_PATH);
  clientCertPem = readFile(FS_CERT_PATH);

  logLine("Device ID: " + getDeviceId());
  logLine("Channel: " + getChannel());
  logLine("Current version: " + getCurrentVersion());
  if (!getCurrentVersion().length()) {
    setCurrentVersion(APP_VERSION);
  }
  lcdShow("Current", getCurrentVersion());

  runOtaCycle();
}

void loop() {
  static uint32_t lastPoll = millis();
  if (millis() - lastPoll >= POLL_INTERVAL_MS) {
    lastPoll = millis();
    runOtaCycle();
  }
  delay(100);
}
