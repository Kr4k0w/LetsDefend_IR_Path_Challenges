# 🚨 Incident Response Report: HTTP Basic Auth

| Metadata | Details |
| :--- | :--- |
| **Event ID** | `SOC - HTTP Basic Auth Analysis` |
| **Event Title** | HTTP Basic Authentication Analysis & Credential Extraction |
| **Severity** | 🔴 **High** |
| **Date Analyzed** | 2026-10-29 |
| **Status** | 🟢 **True Positive** |

---

## 1. 📋 Summary

The alert refers to network requests aiming for HTTP Basic Authentication over an unencrypted channel, allowing the extraction of client request details and plaintext credentials (encoded in Base64).

* **Rule Name:** HTTP Basic Authentication Exposure / Plaintext Credential Leakage
* **Hostname / Affected IP:** Destination Server `1.1.1.5` (Internal Host: `192.168.63.100`) / Client IP: `192.168.63.20`
* **User:** `webadmin`
* **Vector:** Web (HTTP / Port 80)

---

## 2. 🔍 Playbook Steps & Investigation

### Step 1: Verification & Triage
* Analyzed network packet capture (`.pcap`) details in **Wireshark** to identify HTTP `GET` requests and inspect request/response headers.
* **Observations:** The capture contained a total of **5 HTTP GET requests**. Unencrypted HTTP was observed on port 80, exposing session details and transmitted credentials.

### Step 2: Log Analysis (Log Management / Network Analysis)
* **Logs Verified:** Network Packet Capture (`.pcap` / Wireshark)
* **Key Findings:**
  * **Client Information:**
    * **Source IP:** `192.168.63.20`
    * **User-Agent:** `Lynx/2.8.7rel.1 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8n` *(Text-based browser)*
  * **Server Information:**
    * **Server OS:** FreeBSD
    * **Web Server & Version:** `Apache/2.2.15`
    * **OpenSSL Version:** `OpenSSL/0.9.8n`
  * **Authentication Analysis (Basic Auth):**
    * Identified the header: `Authorization: Basic d2ViYWRtaW46VzNiNERtMW4=` sent in the HTTP request.
    * Decoded the Base64 token (`d2ViYWRtaW46VzNiNERtMW4=`), extracting plaintext credentials:
      * **Username:** `webadmin`
      * **Password:** `W3b4Dm1n`

---

## 3. 🛡️ Artifacts & Indicators of Compromise (IoCs)

| Type | Value / Indicator | Status / Reputation |
| :--- | :--- | :--- |
| **Source IP (Client)** | `192.168.63.20` | Internal / Request Origin |
| **Destination IP (Server)** | `1.1.1.5` / `192.168.63.100` | Internal / Apache Web Server |
| **User-Agent** | `Lynx/2.8.7rel.1 libwww-FM/...` | CLI Browser (Lynx) |
| **Exposed Credential (User)**| `webadmin` | ⚠️ Compromised |
| **Exposed Credential (Pass)**| `W3b4Dm1n` | ⚠️ Compromised |

---

## 4. 🛠️ Containment & Remediation

- [x] **Credential Reset:** Immediate password reset for the affected `webadmin` account.
- [x] **Protocol Migration (HTTPS):** Disable unencrypted HTTP authentication (Port 80) and enforce HTTPS (TLS/SSL) to protect the `Authorization` header.
- [x] **Software Upgrade:** Upgrade the outdated Apache (`2.2.15`) and OpenSSL (`0.9.8n`) versions to patch known vulnerabilities.
- [x] **Host Isolation / Firewall Rules:** Restrict administrative web access strictly to authorized internal management IPs.

---

## 5. 🎯 Conclusion & Key Takeaways

* **Verdict:** **True Positive**
* **Key Takeaways:**
  * HTTP Basic Authentication uses Base64 encoding (which is **not** encryption), making credential extraction effortless via passive traffic analysis.
  * Applied Wireshark display filters (`http.request.method == "GET"`, `http.user_agent`, TCP Stream analysis) to inspect web traffic and perform OS/software fingerprinting.
