# 🛡️ SpamShield: Next-Gen Serverless Secure Email Gateway

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Architecture](https://img.shields.io/badge/architecture-Serverless-orange.svg)
![Security](https://img.shields.io/badge/security-Zero--Gap-success.svg)
![Cost](https://img.shields.io/badge/FinOps-Optimized-brightgreen.svg)

**SpamShield** is an enterprise-grade, serverless Secure Email Gateway (SEG) built as a Chrome Extension. It goes beyond simple text classification by utilizing a **7-Layer Defense-in-Depth** architecture and Advanced NLP (ViBert) to protect users from sophisticated phishing, spoofing, and malware attacks in real-time.

---

## ✨ Core Features

*   **🚦 3-Tier Classification System:** Accurately categorizes emails into **HAM** (Safe), **SPAM** (Junk/Promo), and **SCAM** (Phishing/Malicious) with detailed probability scores.
*   **🧠 Hybrid AI Engine:** 
    *   **Standard Mode:** Uses FastText for ultra-fast, lightweight daily spam filtering.
    *   **Pro Mode:** Utilizes a fine-tuned **ViBert** (Vietnamese RoBERTa) model hosted on AWS SageMaker for deep semantic analysis of manipulative text.
*   **💸 FinOps & Scale-to-Zero:** Designed with strict Cost-Awareness. The entire AWS backend (Lambda + SageMaker Serverless) scales to exactly zero when not in use, costing $0 during idle times. DynamoDB TTL automates database cleanup.

---

## 🔐 Zero-Gap Security (7-Layer Defense)

Unlike traditional filtering tools, SpamShield is hardened against modern bypass techniques:

1.  **Network Header Forensics:** Extracts `Authentication-Results` and `Received:` chains to expose Originating IPs, defeating DMARC/SPF bypass via trial third-party mailers (e.g., SendGrid/Mailchimp spoofing).
2.  **Strict eTLD+1 Whitelisting:** Prevents Subdomain Attacks (e.g., `accounts.google.com.evil.com`) by strictly extracting and verifying the registered domain.
3.  **Adversarial Text Sanitization:** A robust NLP pre-processing pipeline that neutralizes Zero-width characters, Homoglyphs, Leet-speak, and Sentence Splitting evasion tactics.
4.  **Polyglot Malware Inspection:** Analyzes Magic Bytes (Hex signatures) of attachments to catch malware disguised under safe extensions (e.g., a PDF containing a hidden ZIP/EXE payload).
5.  **Conditional Cache Bypass:** Defeats "Cache Poisoning" (spear-phishing attacks using aged domains) by forcing AI re-evaluation if emergency trigger words are detected.
6.  **QRishing Readiness:** Architecture prepared for QR code Base64 extraction to combat malicious links hidden in images.
7.  **Automated Threat Intelligence:** A background microservice (EventBridge + Lambda) synchronizes global malicious URLs from Abuse.ch hourly.

---

## 🏛️ System Architecture

SpamShield utilizes a microservices architecture hosted entirely on AWS:

*   **Client Edge:** Chrome Extension V3 (`background.js` Service Worker) handles DOM extraction and asynchronous polling.
*   **Main Worker (AWS Lambda):** The core router that executes heuristics (Levenshtein, WHOIS, DNS checks) and orchestrates AI inference.
*   **Inference Engine (Amazon SageMaker):** Serverless Endpoint running the PyTorch container for the ViBert model.
*   **Threat Intel Bot (AWS Lambda):** An isolated worker syncing URLhaus data hourly.
*   **Storage (DynamoDB):** Caches reputation scores and blacklists with automated TTL (Time-To-Live) expiration.

---

## 🚀 Installation & Setup

### 1. Extension Setup
1. Clone this repository.
2. Open Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode** (top right).
4. Click **Load unpacked** and select the extension directory.

### 2. AWS Backend Deployment
*(Note: AWS deployment requires setting up IAM Roles, API Gateways, and SageMaker models. Detailed terraform/cloudformation scripts are WIP).*
*   Deploy `lambda_function.py` to the Main Worker Lambda.
*   Deploy `threat_intel_sync.py` to a secondary Lambda with an EventBridge rate(1 hour) trigger.
*   Ensure DynamoDB tables (`spamshield-jobs`, `spamshield-reputation`, `spamshield-threat-intel`) are active with `expires_at` TTL configured.

---

## 🎓 About

This project was developed as a **Graduation Thesis** demonstrating the intersection of **Cybersecurity (SecOps)**, **Cloud Architecture (FinOps)**, and **Artificial Intelligence (NLP)**. 

**Disclaimer:** This tool is for educational and research purposes. Do not use the threat intelligence feeds for commercial purposes without adhering to the respective providers' licenses.
