# 🛡️ Incident Response Report: HTTP/2 Rapid Reset

| Field | Details |
| :--- | :--- |
| **Event ID** | Challenge - HTTP/2 Rapid Reset |
| **Event Title** | HTTP/2 Rapid Reset Attack Analysis (CVE-2023-44487) |
| **Severity** | 🔴 High |
| **Date Analyzed** | 2026-10-30 |
| **Status** | 🎯 True Positive |

---

## 1. Summary

Analysis of a network packet capture (PCAP) involving a **Denial of Service (DoS)** attack utilizing the **HTTP/2 Rapid Reset** technique. The attacker exploited the protocol's stream cancellation mechanism to overload the target application server without completing full request-response cycles.

- **Rule Name:** HTTP/2 Protocol Abuse / Rapid Reset DoS
- **Hostname / Affected IP:** `127.0.0.1:4433`
- **User:** N/A (Network Traffic Analysis)
- **Vector:** Web / Transport Layer Security (TLS/HTTP2)

---

## 2. Playbook Steps & Investigation

### Step 1: Verification & Triage
* **Protocol & Cipher Suite Analysis:** Inspected the TLS Handshake packets (`Server Hello`, display filter: `tls.handshake.type == 2`) to identify the security parameters negotiated.
* **Observations:** The server negotiated the protocol using ALPN (`h2`) and confirmed the active cipher suite: **`TLS_AES_256_GCM_SHA384`**.

### Step 2: Log Analysis (Traffic Analysis via Wireshark)
* **Filters Applied:** 
  - `tls`
  - `http2`
  - `http2.type == HEADERS`
  - `http2.type == 13` (`RST_STREAM`)
  - `http2.type == 7` (`GOAWAY`)

* **Key Findings:**
  * **Initial URI Request:** `https://127.0.0.1:4433/foo`
  * **Server Hosting Library:** Identified as **`nghttpd`** via HTTP/2 response headers.
  * **Total HTTP/2 Requests:** **`2008`** requests recorded during the session.
  * **HTTP Status Code:** `404 Not Found` returned by the server for the requested path.
  * **Attack Pattern:** The attacker initiated stream requests and immediately issued **`RST_STREAM`** frames to cancel them before completion, forcing the server to process connection overhead rapidly.
  * **Session Closure:** The server eventually terminated the abusive connection by issuing a **`GOAWAY`** frame.

---

## 3. Artifacts & Indicators of Compromise (IoCs)

| Type | Value / Indicator | Status / Description |
| :--- | :--- | :--- |
| **CVE Identifier** | `CVE-2023-44487` | Known HTTP/2 Rapid Reset Vulnerability |
| **Requested URL** | `https://127.0.0.1:4433/foo` | Target Endpoint |
| **Server Library** | `nghttpd` | Target HTTP/2 Implementation |
| **Cipher Suite** | `TLS_AES_256_GCM_SHA384` | Verified Active Cipher |
| **Abused Frame** | `RST_STREAM` | Attack Trigger Mechanism |
| **Termination Frame** | `GOAWAY` | Connection Termination Indicator |

---

## 4. Containment & Remediation

Recommended mitigation steps for production environments:

- [x] **Rate Limiting:** Implement strict rate limits on incoming `RST_STREAM` frames per connection at the reverse proxy or Web Application Firewall (WAF) layer.
- [x] **Patching:** Update web servers, load balancers, and HTTP/2 libraries (including `nghttpd`) to patched versions enforcing concurrency limits.
- [x] **Connection Termination:** Configure automated session termination (sending `GOAWAY` frames) when rapid reset thresholds are exceeded.

---

## 5. Conclusion & Key Takeaways

* **Verdict:** **True Positive**
* **Key Takeaways:**
  1. Understood how multiplexing in HTTP/2 can be abused for resource exhaustion without completing full request-response cycles.
  2. Mastered Wireshark display filters for isolating TLS negotiation and specific HTTP/2 frame types (`
