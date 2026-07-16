# 🛡️ SpamShield AI — Next-Gen Secure Email Gateway (SEG)

![AWS](https://img.shields.io/badge/AWS-Serverless-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.9-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Llama 3.1](https://img.shields.io/badge/AI-Llama_3.1-0466C8?style=for-the-badge&logo=meta&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active_Development-28A745?style=for-the-badge)

**SpamShield AI** là hệ thống phát hiện thư rác (spam) và lừa đảo (scam) tiếng Việt, được xây dựng trên kiến trúc serverless của AWS. Hệ thống kết hợp mô hình học sâu (PhoBERT) và học máy truyền thống (FastText) với cơ chế Teacher-Student sử dụng Groq Llama 3.1 để tự động cải thiện độ chính xác theo thời gian.

---

## 🏗️ Kiến trúc hệ thống

Dự án được thiết kế theo mô hình **Event-Driven Architecture**, chia làm 4 phân hệ chính:

| Layer | Thành phần | Vai trò |
|---|---|---|
| **Frontend** | Chrome Extension (Manifest V3) | Giao diện người dùng, trích xuất email, hiển thị kết quả |
| **Auth** | Amazon Cognito (User Pool) | Đăng ký, đăng nhập, quên mật khẩu, Google OAuth |
| **API Gateway** | Amazon API Gateway | Cổng vào duy nhất, route request đến Lambda đúng |
| **Orchestration** | Lambda (submit/poll/shutdown/intel) | Điều phối luồng job, quản lý trạng thái |
| **AI Engine** | SageMaker + Groq Llama 3.1 | Suy luận AI (PhoBERT/FastText) + Teacher đánh giá |

---

## ✨ Tính năng nổi bật

### 1. Phân loại 3 lớp (Ham / Spam / Scam)
- **Ham:** Email an toàn, giao dịch thật, công việc.
- **Spam:** Quảng cáo, tiếp thị, khuyến mãi, bản tin.
- **Scam:** Lừa đảo, giả mạo ngân hàng, yêu cầu OTP/mật khẩu, trúng thưởng giả.

### 2. Cơ chế Teacher-Student (Active Learning)
- **Student (PhoBERT):** Chạy nhanh, trả kết quả sơ bộ (1–2s).
- **Teacher (Groq Llama 3.1):** Đánh giá lại email có độ tin cậy thấp.
- **Nếu khác ý kiến:** Lưu vào Retrain Pool → dùng để fine-tune PhoBERT sau mà không cần gán nhãn thủ công.

### 3. Ma trận phòng thủ 7 lớp

| Lớp | Công nghệ | Mục đích |
|---|---|---|
| 1. Header Forensics | DMARC/SPF, Received chain | Phát hiện email giả mạo |
| 2. Domain Impersonation | eTLD+1, WHOIS | Phát hiện tên miền nhái (vcb.com.vn.evil.net) |
| 3. Polyglot Malware | Magic Bytes (hex header) | Phát hiện file đính kèm độc hại |
| 4. Threat Intelligence | Abuse.ch URLhaus | Kiểm tra URL trong danh sách đen |
| 5. Adversarial Text | Leet-speak, zero-width chars | Chuẩn hóa teencode (t4i kh04n → tài khoản) |
| 6. DNS Security | SPF/DMARC lookup | Kiểm tra bảo mật tên miền gửi |
| 7. Whitelist/Blacklist | DynamoDB cache | Giảm gọi AI với domain quen thuộc |

### 4. Tối ưu chi phí (FinOps)

| Cơ chế | Chi tiết |
|---|---|
| **Serverless** | Lambda, API Gateway, DynamoDB → chỉ trả tiền khi có request |
| **SageMaker Serverless** | Tự động scale về 0 khi không có traffic |
| **TTL DynamoDB** | Tự xóa dữ liệu cũ sau 1h (job) / 7 ngày (cache) |
| **Reputation Cache** | Domain quen thuộc được cache → giảm số lần gọi AI đắt tiền |
| **Lambda Shutdown** | 1 click xóa toàn bộ SageMaker resources → không tốn phí |

---

## 🔐 Authentication (Amazon Cognito)

Extension dùng **Amazon Cognito User Pool** để quản lý tài khoản, hỗ trợ đăng ký/đăng nhập bằng email + mật khẩu và đăng nhập Google (OAuth qua Hosted UI).

**Cấu hình:**

| Thông tin | Giá trị |
|---|---|
| User Pool ID | `ap-southeast-1_sRoVGnuUR` |
| App Client ID | `2f5dtlrjh5qp6ltvf4q7nqru6k` |
| Domain | `ap-southeast-1srovgnuur.auth.ap-southeast-1.amazoncognito.com` |
| Region | `ap-southeast-1` |
| Sign-in options | Username + Email (email được cấu hình làm alias) |
| Auth flow bắt buộc bật | `ALLOW_USER_PASSWORD_AUTH` (App client → Authentication flows) |

**Lưu ý kỹ thuật quan trọng:**
- Username khi đăng ký được sinh ngẫu nhiên dạng `user_<uuid>`; email chỉ là **user attribute** (alias), không phải username gốc.
- Đăng nhập email/mật khẩu gọi trực tiếp **Cognito Identity Provider API** (`InitiateAuth` với `AuthFlow=USER_PASSWORD_AUTH`), **không** dùng endpoint `/oauth2/token` của Hosted UI — endpoint đó chỉ hỗ trợ `authorization_code`, `client_credentials`, `refresh_token`, không hỗ trợ `password` grant.
- Đăng nhập Google dùng Hosted UI (`/oauth2/authorize` với `identity_provider=Google`) qua `chrome.identity.launchWebAuthFlow`.
- Token (`IdToken`, `AccessToken`, `RefreshToken`) được lưu trong `chrome.storage.local`.

Chi tiết quá trình debug và fix của module đăng nhập: xem `HANDOFF.md`.

---

## 🛠️ Tech Stack

### Cloud Infrastructure (AWS)
- **Compute:** AWS Lambda (submit/poll/worker/shutdown/intel)
- **API:** Amazon API Gateway
- **Auth:** Amazon Cognito (User Pool + Hosted UI)
- **Queue:** Amazon SQS (`spamshield-queue`)
- **Database:** Amazon DynamoDB (jobs, reputation, threat-intel, retrain-pool)
- **Storage:** Amazon S3 (model FastText 230MB)
- **AI:** Amazon SageMaker (PhoBERT + FastText endpoints)

### Machine Learning

| Model | Framework | Mục đích |
|---|---|---|
| **FastText** | fasttext | Standard mode — nhanh, nhẹ, chạy CPU |
| **PhoBERT** | PyTorch, Transformers | Pro mode — hiểu ngữ cảnh tiếng Việt |
| **Groq Llama 3.1** | Groq API | Teacher — đánh giá email phức tạp |

### Frontend
- **Extension:** Chrome Manifest V3
- **Language:** JavaScript (`background.js`, `popup.js`, `login.js`)
- **DOM Extraction:** `chrome.scripting.executeScript()`

---

## 📊 Hiệu năng

| Model | Precision | Recall | F1-score | Train / Val / Test |
|---|---|---|---|---|
| **FastText** | 0.9191 | 0.9191 | 0.9191 | 2.864 / – / 717 |
| **PhoBERT** | – | – | 0.9655 | 3.755 / 1.073 / 537 |

---

## 🔄 Luồng hoạt động

```
1. User click "Quét" trên extension
   ↓
2. background.js trích xuất email từ Gmail DOM
   ↓
3. Gọi API Gateway → /submit-job → lambda_submit_job.py
   ↓
4. lambda_submit_job.py:
   - Tạo job_id (UUID)
   - Ghi vào DynamoDB (status = pending)
   - Đẩy vào SQS
   - Trả job_id về extension
   ↓
5. Extension bắt đầu polling → /poll-job mỗi 3s
   ↓
6. lambda_worker.py kéo job từ SQS:
   - Standard: FastText trên SageMaker
   - Pro: PhoBERT trên SageMaker + Groq Llama 3.1
   - So sánh Student vs Teacher → lưu retrain nếu khác
   - Áp dụng rule engine (DMARC, WHOIS, threat intel)
   - Cập nhật DynamoDB (status = done)
   ↓
7. lambda_poll_job.py thấy status = done → trả result
   ↓
8. Extension hiển thị kết quả trên popup.html
```

---

## ⚙️ Cài đặt & Triển khai

### Yêu cầu
- AWS Account (IAM role: S3, SageMaker, DynamoDB, Lambda, API Gateway, SQS, Cognito)
- Groq API Key
- Trình duyệt Chromium (Chrome/Edge/Brave)

### Cấu hình biến môi trường (Lambda Worker)

```
GROQ_API_KEY="your_groq_api_key_here"
```

### Deploy Backend
1. Upload code lên Lambda functions
2. Tạo SageMaker endpoints (FastText + PhoBERT)
3. Tạo DynamoDB tables: `spamshield-jobs`, `spamshield-reputation`, `spamshield-threat-intel`, `spamshield-retrain-pool`
4. Tạo SQS queue: `spamshield-queue`
5. Tạo Cognito User Pool, bật `ALLOW_USER_PASSWORD_AUTH` cho App Client, cấu hình Google làm Identity Provider (nếu dùng Google login)
6. Cấu hình API Gateway routes:
   - `POST /submit-job` → lambda_submit
   - `GET /poll-job` → lambda_poll
   - `POST /shutdown` → lambda_shutdown

### Cài Extension
1. Mở `chrome://extensions/`
2. Bật "Developer mode"
3. Click "Load unpacked" → chọn thư mục extension

---

## 📁 Cấu trúc code

| File | Nhiệm vụ |
|---|---|
| `code_fasttext.txt` | Huấn luyện FastText trên Kaggle → deploy SageMaker |
| `code_vibert.txt` | Huấn luyện PhoBERT trên Kaggle → deploy SageMaker |
| `lambda_submit_job.py` | Nhận email → tạo job_id → ghi DB → đẩy SQS |
| `lambda_poll_job.py` | Kiểm tra trạng thái job trong DynamoDB |
| `lambda_worker.py` | Kéo SQS → gọi SageMaker + Groq → cập nhật DB |
| `lambda_shutdown.py` | Xóa SageMaker resources → đóng băng worker |
| `spam_shield_intel_sync.py` | Sync URL độc hại từ Abuse.ch vào DynamoDB |
| `background.js` | Extension service worker |
| `popup.html` / `popup.js` | Extension UI (hiển thị kết quả quét) |
| `login.html` / `login.js` | Extension UI đăng nhập/đăng ký (Cognito) |
| `env.js` | Cấu hình `COGNITO_CONFIG` (domain, appClientId, region) |

---

## 📝 License
MIT © SpamShield AI Team

---

## 🙏 Acknowledgments
- [PhoBERT](https://huggingface.co/vinai/phobert-base-v2) by VinAI
- [FastText](https://fasttext.cc/) by Facebook AI Research
- [Groq Llama 3.1](https://groq.com/) by Groq
- [Abuse.ch URLhaus](https://urlhaus.abuse.ch/) for threat intelligence
