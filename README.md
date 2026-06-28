<div id="readme-content" style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; max-width: 900px; margin: 0 auto; padding: 20px; background: #0d1117; color: #c9d1d9; border-radius: 12px;">

<h1 style="color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px;">🛡️ SpamShield AI — Next-Gen Secure Email Gateway (SEG)</h1>

<p>
  <img src="https://img.shields.io/badge/AWS-Serverless-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white" alt="AWS">
  <img src="https://img.shields.io/badge/Python-3.9-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/AI-Llama_3.1-0466C8?style=for-the-badge&logo=meta&logoColor=white" alt="Llama 3.1">
  <img src="https://img.shields.io/badge/Status-Code_Freeze-28A745?style=for-the-badge" alt="Status">
</p>

<p><strong>SpamShield AI</strong> là hệ thống phát hiện thư rác (spam) và lừa đảo (scam) tiếng Việt, được xây dựng trên kiến trúc serverless của AWS. Hệ thống kết hợp mô hình học sâu (PhoBERT) và học máy truyền thống (FastText) với cơ chế Teacher-Student sử dụng Groq Llama 3.1 để tự động cải thiện độ chính xác theo thời gian.</p>

<hr style="border-color: #30363d;">

<h2 style="color: #58a6ff;">🏗️ Kiến trúc Hệ thống</h2>

<p>Dự án được thiết kế theo mô hình <strong>Event-Driven Architecture</strong>, chia làm 4 phân hệ chính:</p>

<table style="width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px;">
  <thead>
    <tr style="border-bottom: 2px solid #30363d;">
      <th style="padding: 10px; text-align: left;">Layer</th>
      <th style="padding: 10px; text-align: left;">Thành phần</th>
      <th style="padding: 10px; text-align: left;">Vai trò</th>
    </tr>
  </thead>
  <tbody>
    <tr style="border-bottom: 1px solid #21262d;">
      <td style="padding: 10px;"><strong>Frontend</strong></td>
      <td style="padding: 10px;">Chrome Extension (Manifest V3)</td>
      <td style="padding: 10px;">Giao diện người dùng, trích xuất email, hiển thị kết quả</td>
    </tr>
    <tr style="border-bottom: 1px solid #21262d;">
      <td style="padding: 10px;"><strong>API Gateway</strong></td>
      <td style="padding: 10px;">Amazon API Gateway</td>
      <td style="padding: 10px;">Cổng vào duy nhất, route request đến Lambda đúng</td>
    </tr>
    <tr style="border-bottom: 1px solid #21262d;">
      <td style="padding: 10px;"><strong>Orchestration</strong></td>
      <td style="padding: 10px;">Lambda (submit/poll/shutdown/intel)</td>
      <td style="padding: 10px;">Điều phối luồng job, quản lý trạng thái</td>
    </tr>
    <tr>
      <td style="padding: 10px;"><strong>AI Engine</strong></td>
      <td style="padding: 10px;">SageMaker + Groq Llama 3.1</td>
      <td style="padding: 10px;">Suy luận AI (PhoBERT/FastText) + Teacher đánh giá</td>
    </tr>
  </tbody>
</table>

<hr style="border-color: #30363d;">

<h2 style="color: #58a6ff;">✨ Tính năng nổi bật</h2>

<h3 style="color: #f0883e;">1. Phân loại 3 lớp (Ham / Spam / Scam)</h3>
<ul>
  <li><strong>Ham:</strong> Email an toàn, giao dịch thật, công việc.</li>
  <li><strong>Spam:</strong> Quảng cáo, tiếp thị, khuyến mãi, bản tin.</li>
  <li><strong>Scam:</strong> Lừa đảo, giả mạo ngân hàng, yêu cầu OTP/mật khẩu, trúng thưởng giả.</li>
</ul>

<h3 style="color: #f0883e;">2. Cơ chế Teacher-Student (Active Learning)</h3>
<ul>
  <li><strong>Student (PhoBERT):</strong> Chạy nhanh, trả kết quả sơ bộ (1-2s).</li>
  <li><strong>Teacher (Groq Llama 3.1):</strong> Đánh giá lại email có độ tin cậy thấp.</li>
  <li><strong>Nếu khác ý kiến:</strong> Lưu vào Retrain Pool → Dùng để fine-tune PhoBERT sau mà không cần gán nhãn thủ công.</li>
</ul>

<h3 style="color: #f0883e;">3. Ma trận phòng thủ 7 lớp</h3>
<table style="width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px;">
  <thead>
    <tr style="border-bottom: 2px solid #30363d;">
      <th style="padding: 10px; text-align: left;">Lớp</th>
      <th style="padding: 10px; text-align: left;">Công nghệ</th>
      <th style="padding: 10px; text-align: left;">Mục đích</th>
    </tr>
  </thead>
  <tbody>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;">1. Header Forensics</td><td style="padding: 10px;">DMARC/SPF, Received chain</td><td style="padding: 10px;">Phát hiện email giả mạo</td></tr>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;">2. Domain Impersonation</td><td style="padding: 10px;">eTLD+1, WHOIS</td><td style="padding: 10px;">Phát hiện tên miền nhái (vcb.com.vn.evil.net)</td></tr>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;">3. Polyglot Malware</td><td style="padding: 10px;">Magic Bytes (hex header)</td><td style="padding: 10px;">Phát hiện file đính kèm độc hại</td></tr>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;">4. Threat Intelligence</td><td style="padding: 10px;">Abuse.ch URLhaus</td><td style="padding: 10px;">Kiểm tra URL trong danh sách đen</td></tr>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;">5. Adversarial Text</td><td style="padding: 10px;">Leet-speak, zero-width chars</td><td style="padding: 10px;">Chuẩn hóa teencode (t4i kh04n → tài khoản)</td></tr>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;">6. DNS Security</td><td style="padding: 10px;">SPF/DMARC lookup</td><td style="padding: 10px;">Kiểm tra bảo mật tên miền gửi</td></tr>
    <tr><td style="padding: 10px;">7. Whitelist/Blacklist</td><td style="padding: 10px;">DynamoDB cache</td><td style="padding: 10px;">Giảm gọi AI với domain quen thuộc</td></tr>
  </tbody>
</table>

<h3 style="color: #f0883e;">4. Tối ưu chi phí (FinOps)</h3>
<table style="width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px;">
  <thead>
    <tr style="border-bottom: 2px solid #30363d;">
      <th style="padding: 10px; text-align: left;">Cơ chế</th>
      <th style="padding: 10px; text-align: left;">Chi tiết</th>
    </tr>
  </thead>
  <tbody>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;"><strong>Serverless</strong></td><td style="padding: 10px;">Lambda, API Gateway, DynamoDB → chỉ trả tiền khi có request</td></tr>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;"><strong>SageMaker Serverless</strong></td><td style="padding: 10px;">Tự động scale về 0 khi không có traffic</td></tr>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;"><strong>TTL DynamoDB</strong></td><td style="padding: 10px;">Tự xóa dữ liệu cũ sau 1h (job) / 7 ngày (cache)</td></tr>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;"><strong>Reputation Cache</strong></td><td style="padding: 10px;">Domain quen thuộc được cache → giảm số lần gọi AI đắt tiền</td></tr>
    <tr><td style="padding: 10px;"><strong>Lambda Shutdown</strong></td><td style="padding: 10px;">1 click xóa toàn bộ SageMaker resources → không tốn phí</td></tr>
  </tbody>
</table>

<hr style="border-color: #30363d;">

<h2 style="color: #58a6ff;">🛠️ Tech Stack</h2>

<h3 style="color: #f0883e;">Cloud Infrastructure (AWS)</h3>
<ul>
  <li><strong>Compute:</strong> AWS Lambda (submit/poll/worker/shutdown/intel)</li>
  <li><strong>API:</strong> Amazon API Gateway</li>
  <li><strong>Queue:</strong> Amazon SQS (spamshield-queue)</li>
  <li><strong>Database:</strong> Amazon DynamoDB (jobs, reputation, threat-intel, retrain-pool)</li>
  <li><strong>Storage:</strong> Amazon S3 (model FastText 230MB)</li>
  <li><strong>AI:</strong> Amazon SageMaker (PhoBERT + FastText endpoints)</li>
</ul>

<h3 style="color: #f0883e;">Machine Learning</h3>
<table style="width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px;">
  <thead>
    <tr style="border-bottom: 2px solid #30363d;">
      <th style="padding: 10px; text-align: left;">Model</th>
      <th style="padding: 10px; text-align: left;">Framework</th>
      <th style="padding: 10px; text-align: left;">Mục đích</th>
    </tr>
  </thead>
  <tbody>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;"><strong>FastText</strong></td><td style="padding: 10px;">fasttext</td><td style="padding: 10px;">Standard mode — nhanh, nhẹ, chạy CPU</td></tr>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;"><strong>PhoBERT</strong></td><td style="padding: 10px;">PyTorch, Transformers</td><td style="padding: 10px;">Pro mode — hiểu ngữ cảnh tiếng Việt</td></tr>
    <tr><td style="padding: 10px;"><strong>Groq Llama 3.1</strong></td><td style="padding: 10px;">Groq API</td><td style="padding: 10px;">Teacher — đánh giá email phức tạp</td></tr>
  </tbody>
</table>

<h3 style="color: #f0883e;">Frontend</h3>
<ul>
  <li><strong>Extension:</strong> Chrome Manifest V3</li>
  <li><strong>Language:</strong> JavaScript (background.js, popup.js)</li>
  <li><strong>DOM Extraction:</strong> chrome.scripting.executeScript()</li>
</ul>

<hr style="border-color: #30363d;">

<h2 style="color: #58a6ff;">📊 Hiệu năng</h2>

<table style="width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px;">
  <thead>
    <tr style="border-bottom: 2px solid #30363d;">
      <th style="padding: 10px; text-align: left;">Model</th>
      <th style="padding: 10px; text-align: left;">Precision</th>
      <th style="padding: 10px; text-align: left;">Recall</th>
      <th style="padding: 10px; text-align: left;">F1-score</th>
      <th style="padding: 10px; text-align: left;">Train / Val / Test</th>
    </tr>
  </thead>
  <tbody>
    <tr style="border-bottom: 1px solid #21262d;">
      <td style="padding: 10px;"><strong>FastText</strong></td>
      <td style="padding: 10px;">0.9191</td>
      <td style="padding: 10px;">0.9191</td>
      <td style="padding: 10px;">0.9191</td>
      <td style="padding: 10px;">2.864 / - / 717</td>
    </tr>
    <tr>
      <td style="padding: 10px;"><strong>PhoBERT</strong></td>
      <td style="padding: 10px;">-</td>
      <td style="padding: 10px;">-</td>
      <td style="padding: 10px;">0.9655</td>
      <td style="padding: 10px;">3.755 / 1.073 / 537</td>
    </tr>
  </tbody>
</table>

<hr style="border-color: #30363d;">

<h2 style="color: #58a6ff;">🔄 Luồng hoạt động</h2>

<pre style="background: #161b22; padding: 16px; border-radius: 8px; border: 1px solid #30363d; overflow-x: auto; color: #c9d1d9;">
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
</pre>

<hr style="border-color: #30363d;">

<h2 style="color: #58a6ff;">⚙️ Cài đặt & Triển khai</h2>

<h3 style="color: #f0883e;">Yêu cầu</h3>
<ul>
  <li>AWS Account (IAM role: S3, SageMaker, DynamoDB, Lambda, API Gateway, SQS)</li>
  <li>Groq API Key</li>
  <li>Trình duyệt Chromium (Chrome/Edge/Brave)</li>
</ul>

<h3 style="color: #f0883e;">Cấu hình biến môi trường (Lambda Worker)</h3>
<pre style="background: #161b22; padding: 12px; border-radius: 8px; border: 1px solid #30363d; color: #c9d1d9;">
GROQ_API_KEY="your_groq_api_key_here"
</pre>

<h3 style="color: #f0883e;">Deploy Backend</h3>
<ol>
  <li>Upload code lên Lambda functions</li>
  <li>Tạo SageMaker endpoints (FastText + PhoBERT)</li>
  <li>Tạo DynamoDB tables: <code>spamshield-jobs</code>, <code>spamshield-reputation</code>, <code>spamshield-threat-intel</code>, <code>spamshield-retrain-pool</code></li>
  <li>Tạo SQS queue: <code>spamshield-queue</code></li>
  <li>Cấu hình API Gateway routes:
    <ul>
      <li><code>POST /submit-job</code> → lambda_submit</li>
      <li><code>GET /poll-job</code> → lambda_poll</li>
      <li><code>POST /shutdown</code> → lambda_shutdown</li>
    </ul>
  </li>
</ol>

<h3 style="color: #f0883e;">Cài Extension</h3>
<ol>
  <li>Mở <code>chrome://extensions/</code></li>
  <li>Bật "Developer mode"</li>
  <li>Click "Load unpacked" → chọn thư mục extension</li>
</ol>

<hr style="border-color: #30363d;">

<h2 style="color: #58a6ff;">📁 Cấu trúc code</h2>

<table style="width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px;">
  <thead>
    <tr style="border-bottom: 2px solid #30363d;">
      <th style="padding: 10px; text-align: left;">File</th>
      <th style="padding: 10px; text-align: left;">Nhiệm vụ</th>
    </tr>
  </thead>
  <tbody>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;"><code>code_fasttext.txt</code></td><td style="padding: 10px;">Huấn luyện FastText trên Kaggle → deploy SageMaker</td></tr>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;"><code>code_vibert.txt</code></td><td style="padding: 10px;">Huấn luyện PhoBERT trên Kaggle → deploy SageMaker</td></tr>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;"><code>lambda_submit_job.py</code></td><td style="padding: 10px;">Nhận email → tạo job_id → ghi DB → đẩy SQS</td></tr>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;"><code>lambda_poll_job.py</code></td><td style="padding: 10px;">Kiểm tra trạng thái job trong DynamoDB</td></tr>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;"><code>lambda_worker.py</code></td><td style="padding: 10px;">Kéo SQS → gọi SageMaker + Groq → cập nhật DB</td></tr>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;"><code>lambda_shutdown.py</code></td><td style="padding: 10px;">Xóa SageMaker resources → đóng băng worker</td></tr>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;"><code>spam_shield_intel_sync.py</code></td><td style="padding: 10px;">Sync URL độc hại từ Abuse.ch vào DynamoDB</td></tr>
    <tr style="border-bottom: 1px solid #21262d;"><td style="padding: 10px;"><code>background.js</code></td><td style="padding: 10px;">Extension service worker</td></tr>
    <tr><td style="padding: 10px;"><code>popup.html</code> / <code>popup.js</code></td><td style="padding: 10px;">Extension UI</td></tr>
  </tbody>
</table>

<hr style="border-color: #30363d;">

<h2 style="color: #58a6ff;">📝 License</h2>
<p>MIT © SpamShield AI Team</p>

<hr style="border-color: #30363d;">

<h2 style="color: #58a6ff;">🙏 Acknowledgments</h2>
<ul>
  <li><a href="https://huggingface.co/vinai/phobert-base-v2" style="color: #58a6ff;">PhoBERT</a> by VinAI</li>
  <li><a href="https://fasttext.cc/" style="color: #58a6ff;">FastText</a> by Facebook AI Research</li>
  <li><a href="https://groq.com/" style="color: #58a6ff;">Groq Llama 3.1</a> by Groq</li>
  <li><a href="https://urlhaus.abuse.ch/" style="color: #58a6ff;">Abuse.ch URLhaus</a> for threat intelligence</li>
</ul>

</div>
