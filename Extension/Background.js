// SpamShield AI — background.js (Service Worker)

const BASE_URL         = 'https://7kjlqf9e5d.execute-api.ap-southeast-1.amazonaws.com';
const API_SUBMIT       = `${BASE_URL}/submit-job`;
const API_POLL         = `${BASE_URL}/poll-job`;
const API_URL_SHUTDOWN = `${BASE_URL}/shutdown`;

const POLL_INTERVAL_MS = 3000;
const POLL_TIMEOUT_MS  = 300000; 
const FETCH_TIMEOUT_MS = 8000;

let _cancelRequested = false;

// ============================================================
let bankDomainSet = new Set();
async function initBankList() {
  if (bankDomainSet.size > 0) return;
  try {
    const resp = await fetch(chrome.runtime.getURL('bank.json'));
    const data = await resp.json();
    if (data.domains_flat) bankDomainSet = new Set(data.domains_flat);
  } catch (e) {
    console.error("Lỗi nạp bank.json:", e);
  }
}

// ============================================================
// THÊM MỚI: Blacklist email lừa đảo từ file scam-emails.json
// ============================================================
let scamEmailSet = new Set();
async function initScamEmailList() {
  if (scamEmailSet.size > 0) return;
  try {
    const resp = await fetch(chrome.runtime.getURL('scam-emails.json'));
    const data = await resp.json();
    if (data.scam_emails) {
      scamEmailSet = new Set(data.scam_emails.map(email => email.toLowerCase()));
      console.log('[SpamShield] Loaded', scamEmailSet.size, 'scam emails from blocklist');
    }
  } catch (e) {
    console.error("Lỗi nạp scam-emails.json:", e);
  }
}

// ============================================================
const VIP_DOMAINS  = [
  'vietcombank.com.vn', 'vcb.com.vn', 'fpt.vn', 'fpt.com.vn',
  'github.com', 'google.com', 'microsoft.com', 'amazon.com', 'apple.com',
  'facebook.com', 'instagram.com', 'linkedin.com', 'twitter.com', 'x.com',
  'shopify.com', 'stripe.com', 'cloudflare.com', 'netflix.com', 'openai.com', 'momo.vn'
];

const ESP_TRACKERS = [
  'sendgrid.net', 'mailchimp.com', 'awstrack.me', 'list-manage.com', 'sg.mail',
  'mailgun.org', 'mandrillapp.com', 'hubspot.net', 'intercom.io'
];

const DOMAIN_ALIASES = {
  'google.com': ['c.gle', 'goo.gl', 'g.co', 'google.com.vn', 'gmail.com', 'drive.google.com', 'docs.google.com'],
  'microsoft.com': ['aka.ms', 'live.com', 'office.com', 'outlook.com', 'hotmail.com', 'azure.com'],
  'facebook.com': ['fb.me', 'fb.com', 'messenger.com', 'meta.com', 'fbcdn.net'],
  'amazon.com': ['awstrack.me', 'amzn.to', 'a.co', 'aws.amazon.com'],
  'shopee.vn': ['shopee.com', 'shopee.co.id'],
  'vietcombank.com.vn': ['vcb.com.vn'],
};

class EdgeShield {
  static getRootDomain(urlOrEmail) {
    try {
      if (!urlOrEmail) return '';
      let domain = urlOrEmail.includes('@') ? urlOrEmail.split('@')[1] : urlOrEmail;
      if (domain.startsWith('http')) domain = new URL(domain).hostname;
      let parts = domain.split('.');
      if (parts.length >= 3 && ['com', 'net', 'org', 'edu', 'gov'].includes(parts[parts.length - 2])) {
        return parts.slice(-3).join('.');
      }
      return parts.length >= 2 ? parts.slice(-2).join('.') : domain; 
    } catch (e) { return ''; }
  }

  static analyzeLinks(senderEmail, urlsArray) {
    let senderRoot = this.getRootDomain(senderEmail);
    let result = { sender_root: senderRoot, is_vip: VIP_DOMAINS.includes(senderRoot), mismatch_score: 0.0, esp_detected: false, highlights: [] };

    if (!senderRoot || !urlsArray || urlsArray.length === 0) return result;

    let mismatchFound = false, matchFound = false;
    let validAliases  = DOMAIN_ALIASES[senderRoot] || [];

    for (let url of urlsArray) {
      if (!url.startsWith('http')) continue;
      let linkRoot = this.getRootDomain(url);
      if (!linkRoot) continue;

      if (ESP_TRACKERS.includes(linkRoot)) { result.esp_detected = true; continue; }

      if (linkRoot === senderRoot || validAliases.includes(linkRoot)) {
        matchFound = true;
      } else {
        mismatchFound = true;
        if (result.highlights.length < 1) result.highlights.push(`Link lạ lệch pha: ${linkRoot}`);
      }
    }
    if (mismatchFound) result.mismatch_score = 0.60;
    else if (matchFound && result.is_vip) result.mismatch_score = -0.40; 
    return result;
  }

  static async getUserThreshold(esp_detected) {
    return new Promise((resolve) => {
      chrome.storage.local.get(['user_bias'], (data) => {
        resolve((esp_detected ? 0.55 : 0.65) + (data.user_bias || 0.0));
      });
    });
  }

  static async isTrustedSender(senderEmail) {
    return new Promise((resolve) => {
      if (!senderEmail) return resolve(false);
      chrome.storage.local.get(['trusted_senders', 'blocked_senders'], (data) => {
        const blocked = data.blocked_senders || [];
        if (blocked.some(b => senderEmail.toLowerCase().includes(b))) {
          resolve(false);
          return;
        }
        const trusted = data.trusted_senders || [];
        resolve(trusted.includes(senderEmail.toLowerCase()));
      });
    });
  }
}

// ============================================================
class AdaptiveQueue {
  constructor() { this.queue = []; this.isProcessing = false; }
  async add(taskFn) {
    return new Promise((resolve, reject) => {
      this.queue.push({ taskFn, resolve, reject });
      this.processNext();
    });
  }
  async processNext() {
    if (this.isProcessing || this.queue.length === 0) return;
    this.isProcessing = true;
    const { taskFn, resolve, reject } = this.queue.shift();
    try {
      const startTime = Date.now();
      const result    = await taskFn();
      if (Date.now() - startTime > 300) await sleep(100);
      resolve(result);
    } catch (error) { reject(error); } 
    finally { this.isProcessing = false; this.processNext(); }
  }
}
const scanQueue = new AdaptiveQueue();

// ============================================================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'START_SCAN') {
    _cancelRequested = false;
    const targetTabId = msg.tabId || (sender.tab ? sender.tab.id : null);
    
    if (!targetTabId) {
        console.error("Lỗi: Không tìm thấy tabId để thực thi script!");
        chrome.runtime.sendMessage({ action: "SCAN_FAILED", error: "Không tìm thấy thông tin Tab trang Web." });
        sendResponse({ ok: false });
        return true;
    }

    scanQueue.add(() => handleScan(msg.mode, targetTabId));
    sendResponse({ ok: true });
  }
  if (msg.action === 'GET_STATUS') {
    chrome.storage.local.get(['scanState'], (r) => sendResponse(r.scanState || {}));
    return true;
  }
  if (msg.action === 'RESET_STATE') {
    setState({ scanning: false, progress: null, result: null, error: null });
    sendResponse({ ok: true });
    return true;
  }
  if (msg.action === 'CANCEL_SCAN' || msg.action === 'STOP_SCAN') {
    _cancelRequested = true;
    setState({ scanning: false, progress: null, result: null, error: '🛑 Đã ngắt hệ thống.' });
    sendResponse({ ok: true });
  }
  if (msg.action === 'TRUST_CURRENT_SENDER') {
    chrome.storage.local.get(['last_scanned_sender', 'trusted_senders'], (data) => {
      if (data.last_scanned_sender) {
        let list = data.trusted_senders || [];
        if (!list.includes(data.last_scanned_sender.toLowerCase())) {
          list.push(data.last_scanned_sender.toLowerCase());
          chrome.storage.local.set({ trusted_senders: list });
        }
      }
    });
    sendResponse({ ok: true });
  }
  if (msg.action === 'SHUTDOWN') {
    handleShutdown();
    sendResponse({ ok: true });
  }

  // ============================================================
  // THÊM MỚI: XỬ LÝ USER_FEEDBACK
  // ============================================================
  if (msg.action === 'USER_FEEDBACK') {
      chrome.storage.local.get({ feedbackHistory: [] }, (data) => {
          const history = data.feedbackHistory;
          history.push({
              timestamp: Date.now(),
              originalPrediction: msg.originalResult.prediction,
              userLabel: msg.label,
              mode: msg.originalResult.mode || 'standard',
              senderDomain: EdgeShield.getRootDomain(msg.originalResult.senderEmail || ''),
              senderEmail: msg.originalResult.senderEmail || '',
          });
          if (history.length > 50) history.shift();
          chrome.storage.local.set({ feedbackHistory: history });
      });

      const payload = {
          text: msg.originalResult.text || '',
          mode: 'feedback',
          sender_domain: EdgeShield.getRootDomain(msg.originalResult.senderEmail || ''),
          original_prediction: msg.originalResult.prediction,
          correct_label: msg.label,
          source: 'user_feedback',
          confidence: msg.originalResult.probability || 0.0,
      };
      fetchWithTimeout(API_SUBMIT, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
      }).then(res => res.json()).then(data => {
          console.log('[Feedback] Đã gửi lên server:', data);
      }).catch(err => {
          console.error('[Feedback] Lỗi gửi:', err);
      });

      sendResponse({ ok: true });
      return true;
  }

  // ============================================================
  // THÊM MỚI: LẤY LỊCH SỬ QUÉT & FEEDBACK
  // ============================================================
  if (msg.action === 'GET_HISTORY') {
      chrome.storage.local.get({ scanHistory: [], feedbackHistory: [] }, (data) => {
          sendResponse(data);
      });
      return true;
  }

  return true;
});

// ============================================================
async function handleScan(mode, tabId) {
  setState({ scanning: true, mode, progress: 'Đang trích xuất dữ liệu...', result: null, error: null });

  const extractPromise = chrome.scripting.executeScript({
    target: { tabId },
    func: () => {
        const textEl = document.querySelector('.a3s');
        const text = textEl ? textEl.innerText : document.body.innerText.substring(0, 1500);

        let senderEmail = '';
        let senderName = '';

        // Layer 1: span.go (Gmail UI hiện tại)
        const goSpan = document.querySelector('span.go');
        if (goSpan) {
            const raw = goSpan.textContent.trim();
            const match = raw.match(/<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?/);
            if (match) {
                senderEmail = match[1];
                console.log('[SpamShield] Layer 1 (span.go):', senderEmail);
            }
        }

        // Layer 2: .gD attribute email
        if (!senderEmail) {
            const gD = document.querySelector('.gD');
            if (gD) {
                senderEmail = gD.getAttribute('email') || '';
                senderName  = gD.getAttribute('name')  || '';
                if (senderEmail) console.log('[SpamShield] Layer 2 (.gD):', senderEmail);
            }
        }

        // Layer 3: span.yP hoặc span.zF trong inbox row đang active
        if (!senderEmail) {
            const activeRow = document.querySelector('tr.zA.yO, tr.x7');
            if (activeRow) {
                const emailSpan = activeRow.querySelector('span.yP, span.zF');
                if (emailSpan) {
                    senderEmail = emailSpan.getAttribute('email') || '';
                    if (senderEmail) console.log('[SpamShield] Layer 3 (active row):', senderEmail);
                }
            }
        }

        // Layer 4: Scan tất cả .gD
        if (!senderEmail) {
            const allGD = document.querySelectorAll('.gD');
            for (const el of allGD) {
                const em = el.getAttribute('email');
                if (em && em.includes('@')) {
                    senderEmail = em;
                    senderName = el.getAttribute('name') || '';
                    console.log('[SpamShield] Layer 4 (.gD scan):', senderEmail);
                    break;
                }
            }
        }

        // Layer 5: Fallback — tìm email trong .g2
        if (!senderEmail) {
            const g2 = document.querySelector('.g2');
            if (g2) {
                const match = g2.textContent.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
                if (match) {
                    senderEmail = match[1];
                    console.log('[SpamShield] Layer 5 (.g2):', senderEmail);
                }
            }
        }

        console.log('[SpamShield] Final senderEmail:', senderEmail || 'KHÔNG TÌM THẤY');

        return {
            text,
            senderEmail,
            senderName,
            links: Array.from(document.querySelectorAll('.a3s a')).map(a => a.href).filter(h => h),
            attachments: Array.from(document.querySelectorAll('[aria-label^="Attachment"]'))
                              .map(n => n.getAttribute('aria-label')).join(' | ')
        };
    }
  });

  // Load tất cả danh sách song song
  const [bankInit, scamInit, results] = await Promise.all([initBankList(), initScamEmailList(), extractPromise]);
  let emailData = results?.[0]?.result || {};

  if (!emailData.text) {
    setState({ scanning: false, error: 'Không tìm thấy nội dung email.' });
    return;
  }

  chrome.storage.local.set({ last_scanned_sender: emailData.senderEmail });
  if (_cancelRequested) return;

  // ============================================================
  // THÊM MỚI: KIỂM TRA DANH SÁCH EMAIL LỪA ĐẢO CỐ ĐỊNH
  // ============================================================
  if (emailData.senderEmail && scamEmailSet.has(emailData.senderEmail.toLowerCase())) {
      const result = {
          prediction: 'scam',
          probability: 1.0,
          highlights: ['🚫 Email này nằm trong danh sách lừa đảo (Chống Lừa Đảo)'],
          mode
      };
      setState({ scanning: false, progress: null, result, error: null });
      sendResultNotification(result);

      // Vẫn lưu lịch sử quét
      const historyEntry = {
          timestamp: Date.now(),
          mode: mode,
          prediction: 'scam',
          probability: 1.0,
          details: { ham: 0, spam: 0, scam: 1.0 },
          highlights: ['🚫 Email này nằm trong danh sách lừa đảo (Chống Lừa Đảo)'],
          senderDomain: EdgeShield.getRootDomain(emailData.senderEmail),
          senderEmail: emailData.senderEmail,
          subject: emailData?.subject || '',
      };
      chrome.storage.local.get({ scanHistory: [] }, (data) => {
          const history = data.scanHistory;
          history.push(historyEntry);
          if (history.length > 50) history.shift();
          chrome.storage.local.set({ scanHistory: history });
      });
      return;
  }

  if (await EdgeShield.isTrustedSender(emailData.senderEmail)) {
    const result = { prediction: 'ham', probability: 0.0, highlights: ['✅ Người gửi an toàn (Sổ tay)'], mode };
    setState({ scanning: false, progress: null, result, error: null });
    sendResultNotification(result);
    return; 
  }

  // ============================================================
  // THÊM MỚI: KIỂM TRA BLACKLIST (CHẶN CỨNG) từ người dùng
  // ============================================================
  const isBlocked = await new Promise((resolve) => {
      chrome.storage.local.get(['blocked_senders'], (data) => {
          const blocked = data.blocked_senders || [];
          resolve(blocked.some(b => emailData.senderEmail.toLowerCase().includes(b)));
      });
  });
  if (isBlocked) {
      const result = { prediction: 'scam', probability: 1.0, highlights: ['🚫 Địa chỉ này nằm trong danh sách chặn của bạn'], mode };
      setState({ scanning: false, progress: null, result, error: null });
      sendResultNotification(result);
      return;
  }

  // ============================================================
  // THÊM MỚI: UNSHORTEN LINKS TRƯỚC KHI PHÂN TÍCH
  // ============================================================
  if (emailData.links && emailData.links.length > 0) {
      const unshortenedLinks = await Promise.all(emailData.links.map(async (link) => {
          if (link.match(/bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|buff\.ly|cutt\.ly|rb\.gy/)) {
              try {
                  const res = await fetchWithTimeout(`https://unshorten.me/api/v2/unshorten?url=${encodeURIComponent(link)}`, {}, 3000);
                  const data = await res.json();
                  return data.resolved_url || link;
              } catch (e) {
                  return link;
              }
          }
          return link;
      }));
      emailData.links = unshortenedLinks;
  }

  const edgeResult = EdgeShield.analyzeLinks(emailData.senderEmail, emailData.links);
  setState({ progress: 'Đang gọi Backend phân tích...' });

  let job_id = null;
  let submitAttempt = 0;
  
  while (submitAttempt < 5) {
    if (_cancelRequested) return;
    try {
      const senderDomain = EdgeShield.getRootDomain(emailData.senderEmail);
      console.log('[SpamShield] Gửi sender_domain:', senderDomain, '| senderEmail:', emailData.senderEmail);

      const res = await fetchWithTimeout(API_SUBMIT, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ 
          text: emailData.text, 
          mode: mode,
          sender_domain: senderDomain,
          raw_headers: "Authentication-Results: mx.google.com; dmarc=pass\nReceived: from sender [" + (senderDomain || "unknown") + "]",
          attachments_b64: {},
          qr_images_b64: []
        }),
      });
      const data = await res.json();
      if (data.job_id) { job_id = data.job_id; break; }
      throw new Error(data.error || 'Không nhận được job_id');
    } catch (err) {
      submitAttempt++;
      if (submitAttempt >= 5) {
        setState({ scanning: false, error: 'Lỗi máy chủ AWS: ' + err.message });
        return;
      }
      setState({ progress: `Gửi thất bại, thử lại (${submitAttempt}/5)...` });
      await sleep(1500);
    }
  }

  if (_cancelRequested) return;
  await pollResult(job_id, edgeResult, emailData);
}

// ============================================================
// POLLING & TỔNG HỢP ĐIỂM SỐ
// ============================================================
async function pollResult(job_id, edgeResult, emailData = {}) {
  const deadline  = Date.now() + POLL_TIMEOUT_MS;
  let failCount = 0;

  while (Date.now() < deadline) {
    if (_cancelRequested) return;
    await sleep(POLL_INTERVAL_MS);
    if (_cancelRequested) return;

    try {
      const res = await fetchWithTimeout(`${API_POLL}?job_id=${job_id}`);
      const data = await res.json();
      failCount = 0;

      if (data.status === 'done') {
        const r = data.result;
        const isStandard = (r.mode === 'standard' || !r.mode);

        let rawScamProb = r.details ? (r.details.scam || 0) : parseFloat(r.raw_scam_prob || 0);

        let ruleScore = 0;
        let ruleHighlights = [];
        const senderDomain = EdgeShield.getRootDomain(emailData?.senderEmail || '');

        if (bankDomainSet.has(senderDomain)) {
          ruleScore -= 0.6; ruleHighlights.push("🏦 Ngân hàng hợp lệ (SBV Verified)");
        }
        
        let attachLower = (emailData?.attachments || '').toLowerCase();
        if (['.exe', '.scr', '.bat', '.vbs', '.js', '.iso'].some(ext => attachLower.includes(ext))) {
          ruleScore += 0.8; ruleHighlights.push("🚨 File đính kèm nguy hiểm (.exe, .bat...)");
        }
        if (['.zip', '.rar', '.7z'].some(ext => attachLower.includes(ext)) && ['hóa đơn', 'biên lai'].some(w => (emailData?.text || '').toLowerCase().includes(w))) {
          ruleScore += 0.4; ruleHighlights.push("⚠️ File nén đính kèm đáng ngờ");
        }

        let isSuperWhitelist = false;
        if (edgeResult.mismatch_score < 0 && !r.dns_penalty_applied) {
            isSuperWhitelist = true;
            ruleScore -= 2.0; 
            ruleHighlights.push("🛡️ Bỏ qua AI: Tổ chức quốc tế uy tín");
        }

        let finalScamProb = Math.max(0.0, Math.min(1.0, rawScamProb + edgeResult.mismatch_score + ruleScore));
        let threshold = await EdgeShield.getUserThreshold(edgeResult.esp_detected);

        let prediction = r.prediction || 'ham'; 
        
        if (isStandard && prediction === 'spam') prediction = 'suspicious';

        if (isSuperWhitelist) {
            prediction = 'ham';
            finalScamProb = 0.0;
        } else {
            if (finalScamProb > threshold) prediction = 'scam';
            else if (finalScamProb > threshold - 0.2 && prediction !== 'spam') prediction = 'suspicious';
        }

        let highlights = [...ruleHighlights, ...(edgeResult.highlights.length > 0 ? edgeResult.highlights : (r.highlights || []))];
        
        let displayProb = 0;
        if (prediction === 'ham') {
            displayProb = r.details ? r.details.ham : (1.0 - finalScamProb);
            if (isSuperWhitelist) displayProb = 1.0; 
        } else if (prediction === 'spam') {
            displayProb = r.details ? r.details.spam : 0;
        } else {
            displayProb = finalScamProb;
        }

        let syncedDetails = r.details ? { ...r.details } : { ham: 1.0, spam: 0.0, scam: 0.0 };

        if (isStandard) {
            syncedDetails.spam = 0.0;
            if (prediction === 'scam' || prediction === 'suspicious') {
                syncedDetails.scam = finalScamProb;
                syncedDetails.ham = Math.max(0, 1.0 - finalScamProb);
            } else {
                syncedDetails.ham = displayProb;
                syncedDetails.scam = Math.max(0, 1.0 - displayProb);
            }
        } else {
            if (prediction === 'scam' || prediction === 'suspicious') {
                syncedDetails.scam = finalScamProb;
                let remain = 1.0 - finalScamProb;
                let currentRemain = (syncedDetails.ham || 0) + (syncedDetails.spam || 0);
                if (currentRemain > 0) {
                    syncedDetails.ham = (syncedDetails.ham / currentRemain) * remain;
                    syncedDetails.spam = (syncedDetails.spam / currentRemain) * remain;
                } else {
                    syncedDetails.ham = remain; syncedDetails.spam = 0.0;
                }
            } else if (prediction === 'ham') {
                syncedDetails.ham = displayProb;
                let remain = 1.0 - displayProb;
                let currentRemain = (syncedDetails.spam || 0) + (syncedDetails.scam || 0);
                if (currentRemain > 0) {
                    syncedDetails.spam = (syncedDetails.spam / currentRemain) * remain;
                    syncedDetails.scam = (syncedDetails.scam / currentRemain) * remain;
                } else {
                    syncedDetails.spam = 0.0; syncedDetails.scam = remain;
                }
            } else if (prediction === 'spam') {
                syncedDetails.spam = displayProb;
                let remain = 1.0 - displayProb;
                let currentRemain = (syncedDetails.ham || 0) + (syncedDetails.scam || 0);
                if (currentRemain > 0) {
                    syncedDetails.ham = (syncedDetails.ham / currentRemain) * remain;
                    syncedDetails.scam = (syncedDetails.scam / currentRemain) * remain;
                } else {
                    syncedDetails.ham = remain; syncedDetails.scam = 0.0;
                }
            }
        }

        syncedDetails.ham = Math.max(0, Math.min(1.0, syncedDetails.ham));
        syncedDetails.spam = Math.max(0, Math.min(1.0, syncedDetails.spam));
        syncedDetails.scam = Math.max(0, Math.min(1.0, syncedDetails.scam));
        let total = syncedDetails.ham + syncedDetails.spam + syncedDetails.scam;
        if (total > 0) {
            syncedDetails.ham /= total;
            syncedDetails.spam /= total;
            syncedDetails.scam /= total;
        }

        const result = {
          prediction:  prediction,
          probability: displayProb, 
          details:     syncedDetails,
          highlights:  highlights,
          mode:        isStandard ? 'standard' : 'pro',
        };

        // ============================================================
        // THÊM MỚI: LƯU LỊCH SỬ QUÉT
        // ============================================================
        const historyEntry = {
            timestamp: Date.now(),
            mode: isStandard ? 'standard' : 'pro',
            prediction: prediction,
            probability: displayProb,
            details: syncedDetails,
            highlights: highlights,
            senderDomain: EdgeShield.getRootDomain(emailData?.senderEmail || ''),
            senderEmail: emailData?.senderEmail || '',
            subject: emailData?.subject || '',
        };
        chrome.storage.local.get({ scanHistory: [] }, (data) => {
            const history = data.scanHistory;
            history.push(historyEntry);
            if (history.length > 50) history.shift();
            chrome.storage.local.set({ scanHistory: history });
        });

        setState({ scanning: false, progress: null, result, error: null });
        sendResultNotification(result);
        return;
      }

      if (data.status === 'failed') {
        const errorMsg = data.error_msg || data.error || 'Lỗi AI không xác định';
        setState({ scanning: false, error: errorMsg });
        notify('❌ Lỗi AI', 'Phân tích thất bại.');
        return;
      }

    } catch (err) {
      failCount++;
      if (failCount >= 5) {
        setState({ scanning: false, error: 'Mất kết nối quá lâu với AWS.' });
        return;
      }
    }
  }

  setState({ scanning: false, error: 'AI xử lý quá lâu (Timeout 5 phút).' });
}

// ============================================================
async function fetchWithTimeout(url, options = {}, timeoutMs = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try { return await fetch(url, { ...options, signal: controller.signal }); } 
  finally { clearTimeout(timer); }
}

function setState(patch) {
  chrome.storage.local.get(['scanState'], (r) => {
    const next = { ...(r.scanState || {}), ...patch, ts: Date.now() };
    chrome.storage.local.set({ scanState: next });
    chrome.runtime.sendMessage({ action: 'STATE_UPDATE', state: next }).catch(() => {});
    
    if (patch.error) {
        chrome.runtime.sendMessage({ action: 'SCAN_FAILED', error: patch.error }).catch(() => {});
    }
    
    if(patch.result) {
        chrome.runtime.sendMessage({ action: 'SCAN_COMPLETE', result: patch.result }).catch(() => {});
    }
  });
}

function sendResultNotification(result) {
  const { prediction, probability, highlights, mode } = result;
  const probPct = isNaN(probability) ? 'N/A' : (probability * 100).toFixed(1);
  const modeLabel = mode === 'pro' ? 'ViBert' : 'FastText';

  let title, body;
  if (prediction === 'ham') { title = '✅ AN TOÀN'; body = `Độ tin cậy: ${probPct}% • ${modeLabel}`; } 
  else if (prediction === 'spam') { title = '🗑️ THƯ RÁC'; body = `Tỉ lệ: ${probPct}% • ${modeLabel}`; } 
  else if (prediction === 'suspicious') { title = '⚠️ ĐÁNG NGỜ!'; body = `Rủi ro: ${probPct}%` + (highlights.length ? ` • ${highlights[0]}` : ''); } 
  else { title = '🚫 LỪA ĐẢO (SCAM)!'; body = `Nguy cơ: ${probPct}%` + (highlights.length ? ` • ${highlights[0]}` : ''); }
  notify(title, body);
}

function notify(title, message) {
  chrome.notifications.create({ type: 'basic', iconUrl: 'icon.png', title, message, priority: 2 });
}

async function handleShutdown() {
  setState({ scanning: false, progress: 'Đang tắt...', result: null, error: null });
  try {
    const res = await fetchWithTimeout(API_URL_SHUTDOWN, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'shutdown' }) });
    if (res.ok) {
      setState({ scanning: false, progress: null, result: null, error: null });
      notify('🔌 Đã tắt', 'Hệ thống AI đã dừng.');
    }
  } catch (err) {
    setState({ scanning: false, error: 'Không thể kết nối tắt.' });
  }
}

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
