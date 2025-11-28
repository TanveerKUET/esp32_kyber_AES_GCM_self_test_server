#include <WiFi.h>
#include "kem.h"

// FreeRTOS (already in ESP32 core)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// mbedTLS GCM for AES-GCM
extern "C" {
  #include "mbedtls/gcm.h"
}

// ================== USER CONFIG ==================
const char* WIFI_SSID     = "SAKIB";
const char* WIFI_PASSWORD = "123456AB";

const uint16_t SERVER_PORT = 5000;
// =================================================

WiFiServer server(SERVER_PORT);

// ---- Helpers: hex encoding/decoding ----
int hexCharToNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
  return -1;
}

String bytesToHex(const uint8_t* data, size_t len) {
  const char* hexmap = "0123456789abcdef";
  String out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    uint8_t b = data[i];
    out += hexmap[b >> 4];
    out += hexmap[b & 0x0F];
  }
  return out;
}

bool hexToBytes(const String& hex, uint8_t* out, size_t outLen) {
  if (hex.length() != outLen * 2) return false;
  for (size_t i = 0; i < outLen; ++i) {
    int hi = hexCharToNibble(hex[2 * i]);
    int lo = hexCharToNibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (hi << 4) | lo;
  }
  return true;
}

// Read a single line terminated by '\n' (strip '\r') with timeout
bool readLine(WiFiClient& client, String& out, uint32_t timeoutMs = 10000) {
  uint32_t start = millis();
  out = "";
  while (millis() - start < timeoutMs) {
    while (client.available()) {
      char c = client.read();
      if (c == '\n') {
        return true;  // line complete
      }
      if (c != '\r') {
        out += c;
      }
    }
    delay(10);
  }
  return false; // timeout
}

// ---- Kyber buffers ----
uint8_t pk[CRYPTO_PUBLICKEYBYTES];
uint8_t sk[CRYPTO_SECRETKEYBYTES];
uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
uint8_t ss[CRYPTO_BYTES];

// Extra buffers for self-test
uint8_t ct_test[CRYPTO_CIPHERTEXTBYTES];
uint8_t ss_enc[CRYPTO_BYTES];
uint8_t ss_dec[CRYPTO_BYTES];

// ===== AES-GCM self-test using shared secret as key =====
bool aes_gcm_self_test(const uint8_t* key, size_t key_len) {
  // We expect key_len == 32 for AES-256
  if (key_len != 32) {
    Serial.println("[-] AES-GCM self-test: key_len != 32 (not AES-256)");
    return false;
  }

  const uint8_t iv[12] = { // 96-bit IV (just fixed for self-test)
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B
  };

  const char* plaintext_str = "Hello PQC AES-GCM!";
  const size_t pt_len = strlen(plaintext_str);
  const uint8_t* plaintext = (const uint8_t*)plaintext_str;

  uint8_t ciphertext[64] = {0};
  uint8_t decrypted[64]  = {0};
  uint8_t tag[16]        = {0};

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  int ret = mbedtls_gcm_setkey(&gcm,
                               MBEDTLS_CIPHER_ID_AES,
                               key,
                               key_len * 8); // bits
  if (ret != 0) {
    Serial.print("[-] AES-GCM setkey failed, ret = ");
    Serial.println(ret);
    mbedtls_gcm_free(&gcm);
    return false;
  }

  // Encrypt
  ret = mbedtls_gcm_crypt_and_tag(
      &gcm,
      MBEDTLS_GCM_ENCRYPT,
      pt_len,
      iv, sizeof(iv),
      nullptr, 0,           // no AAD
      plaintext,
      ciphertext,
      sizeof(tag),
      tag
  );
  if (ret != 0) {
    Serial.print("[-] AES-GCM encrypt failed, ret = ");
    Serial.println(ret);
    mbedtls_gcm_free(&gcm);
    return false;
  }

  Serial.println("[+] AES-GCM encryption OK");
  Serial.print("Plaintext: ");
  Serial.println(plaintext_str);
  Serial.print("Ciphertext (hex, first 64 chars): ");
  Serial.println(bytesToHex(ciphertext, pt_len).substring(0, 64));
  Serial.print("Tag (hex): ");
  Serial.println(bytesToHex(tag, sizeof(tag)));

  // Decrypt & authenticate
  ret = mbedtls_gcm_auth_decrypt(
      &gcm,
      pt_len,
      iv, sizeof(iv),
      nullptr, 0,           // no AAD
      tag, sizeof(tag),
      ciphertext,
      decrypted
  );

  mbedtls_gcm_free(&gcm);

  if (ret != 0) {
    Serial.print("[-] AES-GCM decrypt/auth failed, ret = ");
    Serial.println(ret);
    return false;
  }

  // Compare plaintext and decrypted
  bool match = true;
  for (size_t i = 0; i < pt_len; ++i) {
    if (plaintext[i] != decrypted[i]) {
      match = false;
      break;
    }
  }

  if (!match) {
    Serial.println("[-] AES-GCM self-test FAILED: decrypted != original");
    Serial.print("Decrypted (as string): ");
    decrypted[pt_len] = 0;
    Serial.println((char*)decrypted);
    return false;
  }

  Serial.println("[✓] AES-GCM self-test PASSED: decrypted == original");
  Serial.print("Decrypted: ");
  decrypted[pt_len] = 0;
  Serial.println((char*)decrypted);

  return true;
}

// ================== CRYPTO SERVER TASK ==================
// NOTE: FreeRTOS stack depth is in 32-bit words.
// 8192 words ≈ 32 KB stack for this task.
//static const uint32_t CRYPTO_TASK_STACK_WORDS = 8192;

// Give the crypto task a BIG stack.
// Treat this as "bytes" from your point of view; even if it’s words, it will still fit.
static const uint32_t CRYPTO_TASK_STACK_SIZE = 32768;  // 32 KB


void crypto_server_task(void *pvParameters) {
  (void) pvParameters;

  // --------- 1) Kyber KEM + AES-GCM self-test ----------
  Serial.println("=== Testing Kyber KEM (keypair + enc + dec self-test) ===");

  // 1) Keypair
  int rc = crypto_kem_keypair(pk, sk);
  if (rc != 0) {
    Serial.println("[-] Keypair generation FAILED!");
  } else {
    Serial.println("[+] Keypair generation SUCCESS!");
    Serial.print("PK length: ");
    Serial.println(sizeof(pk));
    Serial.print("SK length: ");
    Serial.println(sizeof(sk));

    String pkHex = bytesToHex(pk, sizeof(pk));
    Serial.println("PK (first 64 hex chars):");
    Serial.println(pkHex.substring(0, 64));

    // 2) Encapsulation
    rc = crypto_kem_enc(ct_test, ss_enc, pk);
    if (rc != 0) {
      Serial.println("[-] crypto_kem_enc FAILED!");
    } else {
      Serial.println("[+] crypto_kem_enc SUCCESS!");
      String ctHex = bytesToHex(ct_test, sizeof(ct_test));
      Serial.println("CT (first 64 hex chars):");
      Serial.println(ctHex.substring(0, 64));

      // 3) Decapsulation
      rc = crypto_kem_dec(ss_dec, ct_test, sk);
      if (rc != 0) {
        Serial.println("[-] crypto_kem_dec FAILED!");
      } else {
        Serial.println("[+] crypto_kem_dec SUCCESS!");

        // 4) Compare shared secrets
        bool match = true;
        for (size_t i = 0; i < CRYPTO_BYTES; ++i) {
          if (ss_enc[i] != ss_dec[i]) {
            match = false;
            break;
          }
        }

        if (match) {
          Serial.println("[✓] KEM self-test PASSED: shared secrets match!");

          String ssHex = bytesToHex(ss_enc, sizeof(ss_enc));
          Serial.print("Shared secret (first 64 hex chars): ");
          Serial.println(ssHex.substring(0, 64));

          // 5) AES-GCM self-test using shared secret as key
          Serial.println();
          Serial.println("=== AES-GCM self-test using shared secret as key ===");
          bool aes_ok = aes_gcm_self_test(ss_enc, CRYPTO_BYTES);
          if (aes_ok) {
            Serial.println("[✓] Combined KEM + AES-GCM self-test PASSED");
          } else {
            Serial.println("[✗] Combined KEM + AES-GCM self-test FAILED");
          }
        } else {
          Serial.println("[✗] KEM self-test FAILED: shared secrets DO NOT match!");
          String ssEncHex = bytesToHex(ss_enc, sizeof(ss_enc));
          String ssDecHex = bytesToHex(ss_dec, sizeof(ss_dec));
          Serial.print("ss_enc (first 64 hex chars): ");
          Serial.println(ssEncHex.substring(0, 64));
          Serial.print("ss_dec (first 64 hex chars): ");
          Serial.println(ssDecHex.substring(0, 64));
        }
      }
    }
  }

  Serial.println();
  Serial.println("=== Crypto server task entering main loop ===");

  // --------- 2) Main server loop (KEM handshake per client) ----------
  for (;;) {
    WiFiClient client = server.available();
    if (!client) {
      delay(50);
      continue;
    }

    Serial.println("\n[+] Client connected");

    // 1) Generate Kyber-512 keypair for this session
    rc = crypto_kem_keypair(pk, sk);
    if (rc != 0) {
      Serial.println("[-] kyber512_keypair failed!");
      client.stop();
      continue;
    }
    Serial.println("[*] Kyber keypair generated");

    // 2) Send public key as "PK:<hex>\n"
    String pkHex = bytesToHex(pk, sizeof(pk));
    client.print("PK:");
    client.print(pkHex);
    client.print("\n");
    Serial.println("[*] Sent public key to client");

    // 3) Receive ciphertext as "CT:<hex>\n"
    String line;
    if (!readLine(client, line)) {
      Serial.println("[-] Timeout waiting for CT line");
      client.stop();
      continue;
    }

    if (!line.startsWith("CT:")) {
      Serial.print("[-] Invalid message from client: ");
      Serial.println(line);
      client.stop();
      continue;
    }

    String ctHex = line.substring(3);
    if (!hexToBytes(ctHex, ct, sizeof(ct))) {
      Serial.println("[-] Failed to parse ciphertext hex");
      client.stop();
      continue;
    }
    Serial.println("[*] Received ciphertext from client");

    // 4) Decapsulate to get shared secret
    rc = crypto_kem_dec(ss, ct, sk);
    if (rc != 0) {
      Serial.println("[-] kyber512_dec failed!");
      client.stop();
      continue;
    }

    String ssHex = bytesToHex(ss, sizeof(ss));
    Serial.print("[+] Shared secret (server): ");
    Serial.println(ssHex);

    Serial.println("[*] Handshake complete, closing connection");
    client.stop();

    // For demo, wait 5s before accepting another client
    delay(5000);
  }

  // Never reached, but good practice:
  vTaskDelete(NULL);
}

// ================== SETUP ==================
void setup() {
  Serial.begin(115200);
  delay(2000);

  Serial.println("=== ESP32 Kyber-512 SERVER (network mode) ===");

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("Connected, IP address: ");
  Serial.println(WiFi.localIP());

  server.begin();
  Serial.print("Server listening on port ");
  Serial.println(SERVER_PORT);

  // Create the crypto server task with a large stack
  xTaskCreatePinnedToCore(
    crypto_server_task,
    "crypto_server_task",
    CRYPTO_TASK_STACK_SIZE, 
    NULL,
    1,                       // priority
    NULL,
    1                        // run on core 1
  );
}

// ================== LOOP ==================
void loop() {
  // Nothing heavy here: all crypto & networking is in crypto_server_task
  delay(1000);
}
