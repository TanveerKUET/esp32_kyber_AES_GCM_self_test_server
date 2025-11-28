# ESP32 Kyber KEM Self-Test + TCP Server

This project turns an **ESP32** into a simple **post-quantum cryptography (PQC) key-exchange server** using:

- **CRYSTALS-Kyber (KEM)** — quantum-safe key exchange  
- **AES-256-GCM** — authenticated encryption using the derived shared secret  
- **TCP server** — clients connect and perform a 1-round Kyber handshake  
- **FreeRTOS dedicated crypto task** — large stack to prevent ESP32 crashes  

The server performs an automatic **KEM + AES-GCM self-test**, then waits for TCP clients.  
Each client establishes a *fresh* Kyber shared secret.

---

## ✨ Features

- 📶 Wi-Fi STA mode  
- 🔐 Full Kyber KEM implementation (`kem.h`, Kyber reference code)  
- 🧪 Power-on self-test:
  - Kyber keypair generation  
  - Encapsulation / decapsulation  
  - Shared secret verification  
  - AES-256-GCM encryption & decryption self-test  
- 🌐 TCP server handshake:
  - Sends public key as: `PK:<hex>\n`
  - Receives ciphertext as: `CT:<hex>\n`
  - Decapsulates to obtain shared secret  
- 🧵 Crypto runs in a **FreeRTOS task with 32 KB stack**
  - Prevents ESP32 "stack canary" crashes from large Kyber buffers  
- 🖥 Clear UART debug output  

---

## 📁 Project Structure

```
/esp32_kyber_AES_GCM_self_test_server/
│── README.md          <-- (this file)
│── esp32_kyber_self_test_server.ino
│── kem.h
│── params.h
│── (Kyber reference source files: indcpa.c, poly.c, ntt.c, etc.)
```

---

## 📡 Wi-Fi Configuration

Edit the following lines in the `.ino` file:

```cpp
const char* WIFI_SSID     = "WIFI_SSID";
const char* WIFI_PASSWORD = "WIFI_PASSWORD";

const uint16_t SERVER_PORT = 5000;
```

---

## 🚀 How It Works (High-Level Flow)

### 1. **Startup**
- ESP32 connects to Wi-Fi  
- TCP server starts on port `5000`  
- A **FreeRTOS crypto task** is created with a 32 KB stack  

### 2. **Kyber + AES-GCM Self-Test**
- Generate keypair  
- Encapsulate shared secret  
- Decapsulate shared secret  
- Verify equality  
- Use the shared secret as a **256-bit AES-GCM key**  
- Encrypt/decrypt `"Hello PQC AES-GCM!"`  

### 3. **Server Loop**
For each TCP client:

1. Generate fresh Kyber keypair  
2. Send public key as hex  
3. Receive ciphertext (hex)  
4. Decapsulate shared secret  
5. Print shared secret to Serial  
6. Close connection  

This creates a **1-round post-quantum key exchange** suitable for IoT devices.

---

## 🔌 TCP Message Format

### Server → Client
```
PK:<hex_of_public_key>\n
```

### Client → Server
```
CT:<hex_of_ciphertext>\n
```

### Server internally:
```cpp
crypto_kem_dec(ss, ct, sk);
```
This yields the shared secret (`ss`).

---

## 🧠 Why FreeRTOS Task?

Kyber uses **large stack-allocated arrays**:

- `polyvec a[KYBER_K]`
- `polyvec sp, ep, at[KYBER_K]`
- `poly v, k, epp`

Total stack usage = **10–12 KB per function call** (keypair/enc/dec).

Arduino `loopTask` only has **~8 KB**, causing:

```
Guru Meditation Error: Stack canary watchpoint triggered (loopTask)
```

This project avoids the crash by running crypto in a **dedicated task**:

```cpp
xTaskCreatePinnedToCore(
    crypto_server_task,
    "crypto_server_task",
    32768,   // 32 KB stack
    NULL,
    1,
    NULL,
    1
);
```

---

## 🧪 AES-GCM Self-Test

After deriving a Kyber shared secret, the server:

- Treats it as a **32-byte AES-256 key**
- Encrypts `"Hello PQC AES-GCM!"`
- Prints ciphertext + authentication tag  
- Decrypts and verifies correctness

This confirms:

✔ Kyber works  
✔ AES-GCM works  
✔ Shared secret is valid  
✔ mbedTLS is functioning on ESP32  

---

## 📜 Serial Output Example

```
rst:0x1 (POWERON_RESET),boot:0x13 (SPI_FAST_FLASH_BOOT)
configsip: 0, SPIWP:0xee
clk_drv:0x00,q_drv:0x00,d_drv:0x00,cs0_drv:0x00,hd_drv:0x00,wp_drv:0x00
mode:DIO, clock div:1
load:0x3fff0030,len:4744
load:0x40078000,len:15672
load:0x40080400,len:3164
entry 0x4008059c

=== ESP32 Kyber-512 SERVER (network mode) ===
=== Testing Kyber KEM (keypair + enc + dec self-test) ===
[+] Keypair generation SUCCESS!
PK length: 800
SK length: 1632
PK (first 64 hex chars):
793b532f53047f3918823212ac9a864c686743570cca6c68ffacb6a5d59561c6
[+] crypto_kem_enc SUCCESS!
CT (first 64 hex chars):
2b7ad58a88229512046fdcc555f86054e44b624820d49c6a2fe4febb2b1b24cd
[✓] KEM self-test PASSED: shared secrets match!
Shared secret (first 64 hex chars): a2bdafb7bb5119cf5621529611033dfe86da897721332338e02176076524d47e
=== Kyber self-test DONE ===
Connecting to WiFi...
Connected, IP address: 192.168.137.93
Server listening on port 5000
```

---


