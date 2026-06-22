# 🛡️ SpamShield AI — Next-Gen Secure Email Gateway (SEG)

![AWS](https://img.shields.io/badge/AWS-Serverless-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.9-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Llama 3.1](https://img.shields.io/badge/AI-Llama_3.1-0466C8?style=for-the-badge&logo=meta&logoColor=white)
![Status](https://img.shields.io/badge/Status-Code_Freeze-28A745?style=for-the-badge)

**SpamShield AI** là hệ thống cổng bảo mật email (Secure Email Gateway) chạy hoàn toàn trên kiến trúc Serverless. Hệ thống kết hợp sức mạnh của mô hình ngôn ngữ lớn (Multi-LLM) và ma trận phòng thủ an ninh mạng nhiều lớp nhằm phân loại email với độ chính xác cao (Ham / Spam / Scam), đồng thời cung cấp khả năng phân tích ngữ cảnh theo thời gian thực (Explainable AI).

---

## 🚀 Kiến trúc Hệ thống (System Architecture)

Dự án được thiết kế theo triết lý **Microservices** và **Event-Driven Architecture**, chia làm 3 phân hệ chính:

1. **Client Edge (Chrome Extension V3):** Giao diện quét email bất đồng bộ, xử lý lazy-loading giúp chống treo main-thread của trình duyệt.
2. **API & Orchestration (AWS API Gateway + Lambda):** Trung tâm điều phối luồng dữ liệu, tích hợp cơ chế Early-Write/Post-Inference giúp loại bỏ độ trễ phản hồi (Zero-latency UI).
3. **Hybrid AI Engine (SageMaker + Groq):** Kết hợp ViBERTa (Fine-tuned cho tiếng Việt) và Llama-3.1-8B-Instant cho phán quyết ngữ cảnh phức tạp.

---

## ✨ Tính năng Cốt lõi & Điểm nhấn Kỹ thuật

### 1. Ma trận Phòng thủ 7 lớp (Zero-Gap Security Matrix)
Thay vì chỉ dựa vào AI chấm điểm văn bản thuần túy, hệ thống bọc lót 7 lỗ hổng mạng phổ biến:
* **Header Forensics:** Phân tích DMARC/SPF và chuỗi `Received:` để truy vết IP giả mạo.
* **Impersonation Prevention:** Super Whitelist và bóc tách eTLD+1 để chặn tên miền nhái (VD: `vcb.com.vn.evil.net`).
* **Polyglot Malware Detection:** Đọc Magic Bytes (Hex header) để lật tẩy mã độc ngụy trang (ZIP ẩn trong PDF).
* **Adversarial Text Cleaning:** Triệt tiêu zero-width characters và Leet-speak (VD: `t4i kh04n`).
* **Threat Intelligence Sync:** Bot EventBridge tự động cào dữ liệu URL độc hại từ tổ chức Abuse.ch mỗi giờ.

### 2. Tối ưu hóa Chi phí (FinOps - Scale to Zero)
* Áp dụng **Amazon SageMaker Serverless Inference**, tự động scale instance về 0 khi không có lưu lượng truy cập (tránh lãng phí GPU nhàn rỗi).
* Sử dụng cơ chế Time-To-Live (TTL) trên **DynamoDB** để tự động dọn rác dữ liệu sau 7 ngày, tối ưu 100% chi phí lưu trữ.
* Cache kết quả quét bằng Rep-Table, giảm thiểu số lần gọi Model đắt tiền.

### 3. Vòng lặp Active Learning Bất đồng bộ
* **Early-Write:** Trả ngay kết quả ViBERTa về Client để đảm bảo tốc độ (1-2s).
* **Post-Inference (Offline Batch Retraining):** Ở hậu trường, nếu ViBERTa rơi vào "vùng xám" (Confidence 40-70%), Llama-3.1 sẽ được gọi để làm trọng tài. Ca sai lệch sẽ tự động lưu vào bảng `spamshield-retrain-pool` phục vụ cho việc Fine-tune mô hình offline hàng tuần mà không ảnh hưởng hiệu năng hệ thống live.

---

## 🛠️ Tech Stack
* **Cloud Infrastructure:** AWS Lambda, Amazon DynamoDB, API Gateway, Amazon S3, EventBridge.
* **Machine Learning:** Amazon SageMaker, FastText, ViBERTa (PhoBERT-based).
* **External AI:** Groq Llama-3.1-8B API (Explainable AI / Context Arbitrator).
* **Frontend/Client:** JavaScript (Chrome Extension Manifest V3).
* **Networking/Security:** `whois`, `dnspython`, Magic Bytes Inspector.

---

## ⚙️ Hướng dẫn Cài đặt & Triển khai

### 1. Yêu cầu hệ thống
* Tài khoản AWS (IAM Role cấp quyền S3, SageMaker, DynamoDB).
* API Key của Groq (Llama 3.1).
* Trình duyệt nền tảng Chromium để nạp Extension.

### 2. Cấu hình Biến môi trường
Tuyệt đối không lưu API Key trực tiếp vào mã nguồn. Vui lòng tham khảo file `.env.example`:
```bash
# Định nghĩa tại mục Configuration -> Environment variables của hàm AWS Lambda 'worker'
GROQ_API_KEY="your_groq_api_key_here"
