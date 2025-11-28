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
/your-repo/
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
const char* WIFI_SSID     = "SAKIB";
const char* WIFI_PASSWORD = "123456AB";

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
=== Testing Kyber KEM (keypair + enc + dec self-test) ===
[+] Keypair generation SUCCESS!
[+] crypto_kem_enc SUCCESS!
[+] crypto_kem_dec SUCCESS!
[✓] KEM self-test PASSED: shared secrets match!

=== AES-GCM self-test using shared secret as key ===
Plaintext: Hello PQC AES-GCM!
[✓] AES-GCM self-test PASSED
=== Crypto server task entering main loop ===
```

---

## 🖥 Example Client (Python)

```python
import socket
from kyber import crypto_kem_enc, hex_encode, hex_decode

HOST = "ESP32_IP_HERE"
PORT = 5000

s = socket.socket()
s.connect((HOST, PORT))

# Receive public key
line = s.recv(4096).decode().strip()
assert line.startswith("PK:")
pk = hex_decode(line[3:])

# Encapsulate
ct, ss = crypto_kem_enc(pk)

# Send ciphertext
s.sendall(b"CT:" + hex_encode(ct).encode() + b"\n")

print("Shared secret:", ss.hex())
s.close()
```

---

## 🛠 Troubleshooting

### ❌ Stack Canary Triggered
- Ensure Kyber operations are *not* inside `loop()` or `setup()`
- Only run in the FreeRTOS crypto task with **≥ 32 KB stack**

### ❌ Client receives no PK
- Ensure both devices are on the same Wi-Fi network  
- Check firewall settings  
- Confirm `SERVER_PORT` is correct  

### ❌ Shared secrets do not match
- Client must use **same Kyber parameter set**:
  - `KYBER_K = 2` → Kyber-512
  - `KYBER_K = 3` → Kyber-768
  - `KYBER_K = 4` → Kyber-1024

---

## 🔐 Security Considerations

This is a **demo**:
- AES-GCM IV is fixed (do **not** use this in production)
- Shared secret printed to Serial
- No authentication or replay protection

For real systems:
- Use random IVs
- Never expose keys
- Add digital signatures (e.g., Dilithium)
- Use secure key derivation (HKDF)

---

## 📜 License

MIT License — free to use, modify, distribute.

---

## ✉️ Contact

For an Android client or BLE-secure version, open an issue.

Happy Post-Quantum IoT Hacking! 🧬🔒  
ESP32 + Kyber = Future-Proof Security 🚀
