from decimal import Decimal
import json
import boto3
import time
import re
import os
import tarfile
import dns.resolver
import whois
import base64
import socket
import concurrent.futures
from datetime import datetime
import botocore.config

# ==========================================
# KHỞI TẠO TÀI NGUYÊN AWS
# ==========================================
dynamodb  = boto3.resource('dynamodb')
sagemaker = boto3.client(
    'sagemaker-runtime',
    config=botocore.config.Config(
        connect_timeout=5,
        read_timeout=20,
        retries={'max_attempts': 1, 'mode': 'standard'}
    )
)
s3 = boto3.client('s3')

TABLE_NAME         = 'spamshield-jobs'
REP_TABLE_NAME     = 'spamshield-reputation'
THREAT_INTEL_TABLE = 'spamshield-threat-intel'
ENDPOINT_PRO       = 'spam-detection-endpoint-final'

S3_BUCKET     = 'spam-detection-doannhom'
S3_MODEL_KEY  = 'standard/output/fasttext/model_standard.tar.gz'
TMP_TAR_PATH  = '/tmp/model_standard.tar.gz'
TMP_MODEL_DIR = '/tmp/fasttext'
TMP_MODEL_BIN = '/tmp/fasttext/model.bin'

_fasttext_model = None

# ==========================================
# MODULE-LEVEL CONSTANTS
# ==========================================
TRIGGER_WORDS = ['chuyển tiền', 'mật khẩu', 'đăng nhập', 'otp', 'khóa tài khoản']

SCAM_KEYWORDS = [
    'chuyển tiền', 'mật khẩu', 'otp', 'khóa tài khoản', 'xác minh',
    'khẩn cấp', 'ngay lập tức', 'cảnh báo', 'bị khóa', 'đăng nhập',
    'trúng thưởng đặc biệt', 'click ngay', 'hết hạn hôm nay'
]

SPAM_KEYWORDS = [
    'khuyến mãi', 'giảm giá', 'sale off', 'ưu đãi', 'miễn phí',
    'quà tặng', 'mua ngay', 'đặt hàng', 'giao hàng', 'voucher',
    'newsletter', 'unsubscribe', 'đăng ký nhận tin'
]

# ==========================================
# CÁC HÀM TIỀN XỬ LÝ VÀ BẢO MẬT
# ==========================================
def advanced_clean_text(text):
    if not text: return ""
    text_cleaned = str(text).lower()
    text_cleaned = re.sub(r'[\u200b-\u200d\ufeff]', '', text_cleaned)
    leet_dict = {
        't4i kh04n': 'tài khoản', 'b1 kh04': 'bị khóa', 'vcb': 'vietcombank',
        'c4nh b4o': 'cảnh báo', 'm4t kh4u': 'mật khẩu', '0tp': 'otp'
    }
    for leet, normal in leet_dict.items():
        text_cleaned = text_cleaned.replace(leet, normal)
    text_cleaned = re.sub(r'\s*\n\s*', ' ', text_cleaned)

    TRUSTED_DOMAINS = {
        'google.com', 'googleapis.com', 'youtube.com', 'facebook.com',
        'microsoft.com', 'apple.com', 'github.com', 'amazon.com',
        'shopee.vn', 'lazada.vn', 'tiki.vn', 'momo.vn',
        'vietcombank.com.vn', 'techcombank.com.vn', 'mbbank.com.vn',
        'gov.vn', 'edu.vn', 'wikipedia.org', 'linkedin.com',
    }
    SHORTENER_PATTERNS = re.compile(
        r'(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|buff\.ly'
        r'|cutt\.ly|rb\.gy|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        re.IGNORECASE
    )

    def _classify_url(m):
        url = m.group(0)
        domain_m = re.search(r'https?://([^/\s?#]+)', url)
        if not domain_m:
            return ' url_unknown '
        domain = domain_m.group(1).lower().lstrip('www.')
        if SHORTENER_PATTERNS.search(domain):
            return ' url_shortener '
        for trusted in TRUSTED_DOMAINS:
            if domain == trusted or domain.endswith('.' + trusted):
                return ' url_trusted '
        safe_domain = re.sub(r'[^\w]', '_', domain)
        return f' url_{safe_domain} '

    text_cleaned = re.sub(r'https?://\S+', _classify_url, text_cleaned)
    text_cleaned = re.sub(r'(0\d{9,10})', ' phone ', text_cleaned)
    text_cleaned = re.sub(r'[^\w\s]', ' ', text_cleaned)
    return re.sub(r'\s+', ' ', text_cleaned).strip()


def _verify_external_intelligence(text):
    import urllib3

    token = os.environ.get('GROQ_API_KEY')
    if not token:
        print("Lỗi hệ thống: Thiếu GROQ_API_KEY")
        return None

    endpoint = "https://api.groq.com/openai/v1/chat/completions"
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {
                "role": "system",
                "content": (
                    "Bạn là chuyên gia phân loại email bảo mật tiếng Việt.\n"
                    "PHÂN LOẠI email thành ĐÚNG 1 trong 3 nhãn:\n\n"
                    "- 'ham': Email cá nhân, giao dịch thật, thông báo tài khoản, "
                    "hóa đơn, xác nhận đặt hàng, email công việc, học tập.\n\n"
                    "- 'spam': Email QUẢNG CÁO, tiếp thị, khuyến mãi, giảm giá, "
                    "bản tin (newsletter), mời mua hàng, 'ưu đãi', 'săn sale', "
                    "'giảm ngay', 'miễn phí vận chuyển', 'đặt hàng ngay'.\n\n"
                    "- 'scam': Email LỪA ĐẢO, giả mạo ngân hàng, yêu cầu OTP/mật khẩu, "
                    "đe dọa khóa tài khoản, trúng thưởng giả, chuyển tiền gấp.\n\n"
                    "QUAN TRỌNG: Email quảng cáo = 'spam', KHÔNG phải 'ham'.\n"
                    "Trả lời CHỈ 1 từ: ham, spam, hoặc scam."
                )
            },
            {"role": "user", "content": text[:1500]}
        ],
        "temperature": 0.1,
        "max_tokens": 10
    }

    try:
        http = urllib3.PoolManager(
            timeout=urllib3.Timeout(connect=2.0, read=4.0)
        )
        response = http.request(
            'POST', endpoint,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {token}'
            },
            body=json.dumps(payload),
            retries=urllib3.Retry(total=1, backoff_factor=0.5)
        )
        if response.status == 200:
            res_data = json.loads(response.data.decode('utf-8'))
            verdict  = res_data['choices'][0]['message']['content'].strip().lower()
            verdict  = re.sub(r'[^a-z]', '', verdict)
            print(f"[Groq] Verdict: {verdict}")
            if verdict in ['ham', 'spam', 'scam']:
                return verdict
        elif response.status == 429:
            print("Groq rate limit — bỏ qua")
    except urllib3.exceptions.TimeoutError:
        print("Groq timeout — bỏ qua")
    except Exception as e:
        print(f"Groq error: {str(e)}")

    return None


def analyze_header_routing(raw_headers):
    verdict = {"is_spoofed": False, "origin_ip": None, "reason": []}
    if not raw_headers: return verdict
    auth_results = re.search(
        r'Authentication-Results:.*?(dmarc=\S+|spf=\S+)', raw_headers, re.IGNORECASE
    )
    if auth_results and "fail" in auth_results.group(0).lower():
        verdict["is_spoofed"] = True
        verdict["reason"].append("🚨 Bẫy Header: Xác thực DMARC/SPF bị giả mạo")
    received_chains = re.findall(
        r'Received:\s*from\s+.*?\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', raw_headers
    )
    if received_chains:
        verdict["origin_ip"] = received_chains[-1]
        if verdict["origin_ip"].startswith(("185.", "45.", "95.")):
            verdict["is_spoofed"] = True
            verdict["reason"].append(f"🚨 IP gốc phát tán rủi ro cao: {verdict['origin_ip']}")
    return verdict


def strict_whitelist_check(sender_domain, global_vip_list):
    if not sender_domain: return False
    pattern = r'([^.]+\.(?:com\.vn|net\.vn|org\.vn|gov\.vn|edu\.vn|com|net|org|io|me|tv|biz))$'
    match = re.search(pattern, sender_domain.lower())
    if match and match.group(1) in global_vip_list:
        return True
    return False


def check_email_security(domain):
    penalty = 0.0
    if not domain:
        return penalty
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 2.0
    resolver.timeout  = 1.0
    try:
        answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
        has_dmarc = any('v=DMARC1' in str(r.strings[0], 'utf-8') for r in answers)
        if not has_dmarc:
            penalty += 0.20
    except Exception:
        penalty += 0.20
    try:
        answers = resolver.resolve(domain, 'TXT')
        has_spf = any('v=spf1' in str(r.strings[0], 'utf-8') for r in answers)
        if not has_spf:
            penalty += 0.10
    except Exception:
        penalty += 0.10
    return penalty


def deep_inspect_magic_bytes(base64_files):
    reasons = []
    penalty = 0.0
    for filename, b64_content in base64_files.items():
        try:
            file_bytes = base64.b64decode(b64_content)
            header = file_bytes[:4]
            has_zip_footer = b'\x50\x4B\x05\x06' in file_bytes
            if header.startswith(b'%PDF') and has_zip_footer:
                penalty += 1.0
                reasons.append(f"🚨 Malware Evasion: {filename} là tệp Polyglot (PDF chứa mã thực thi)")
            elif header.startswith(b'PK\x03\x04') and not filename.endswith('.zip'):
                penalty += 0.5
                reasons.append(f"⚠️ {filename}: Nén ZIP ẩn danh")
        except Exception:
            pass
    return penalty, reasons


def extract_urls_from_text_and_qr(text, qr_base64_list):
    urls = re.findall(r'(https?://[^\s]+)', text)
    if qr_base64_list:
        urls.append("http://malicious-qr-link.com")
    return urls


def check_threat_intel(urls):
    try:
        table = dynamodb.Table(THREAT_INTEL_TABLE)
        for u in urls:
            resp = table.get_item(Key={'entity': u})
            if 'Item' in resp: return True
    except Exception:
        pass
    return False


def apply_penalty_with_context(scores, penalty_signals, text):
    text_lower = text.lower()
    scam_ctx = sum(1 for w in SCAM_KEYWORDS if w in text_lower)
    spam_ctx = sum(1 for w in SPAM_KEYWORDS if w in text_lower)
    for signal in penalty_signals:
        sig_type = signal.get('type')
        weight   = signal.get('weight', 0.0)
        if sig_type in ('header_spoofed', 'malware', 'threat_intel'):
            scores['scam'] = min(1.0, scores['scam'] + weight)
        elif sig_type in ('url_suspicious', 'domain_new', 'domain_impersonation'):
            if scam_ctx >= spam_ctx:
                scores['scam'] = min(1.0, scores['scam'] + weight * 0.6)
            else:
                scores['spam'] = min(1.0, scores['spam'] + weight * 0.4)
        elif sig_type == 'dns_missing':
            scores['scam'] = min(1.0, scores['scam'] + weight * 0.1)
    total = sum(scores.values())
    if total > 1.5:
        scores = {k: v / total for k, v in scores.items()}
    return scores


def safe_whois_check(sender_domain, penalty_signals, highlights):
    if not sender_domain:
        return
    def _do_whois():
        try:
            w = whois.whois(sender_domain)
            if w.creation_date:
                c_date = (w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date)
                return (datetime.now() - c_date).days
        except Exception:
            pass
        return None
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_do_whois)
            age_days = future.result(timeout=3.0)
        if age_days is not None and age_days < 30:
            penalty_signals.append({'type': 'domain_new', 'weight': 0.5})
            highlights.append("🚨 Tên miền sơ sinh (< 30 ngày)")
    except concurrent.futures.TimeoutError:
        print(f"WHOIS timeout: {sender_domain} — bỏ qua")
    except Exception as e:
        print(f"WHOIS lỗi: {str(e)} — bỏ qua")


def save_to_reputation_cache(sender_domain, result):
    if not sender_domain:
        print("[RepCache] Bỏ qua: sender_domain rỗng")
        return
    try:
        dynamodb.Table(REP_TABLE_NAME).put_item(Item={
            'domain'    : sender_domain,
            'result'    : json.loads(json.dumps(result), parse_float=Decimal),
            'expires_at': int(time.time()) + (7 * 24 * 3600),
            'saved_at'  : int(time.time()),
            'label'     : result.get('prediction', 'unknown'),
        })
        print(f"[RepCache] Đã lưu: {sender_domain} → {result.get('prediction')}")
    except Exception as e:
        print(f"[RepCache] Lỗi lưu: {e}")


def _should_save_standard_retrain(top_label, top_score, text):
    if top_score < 0.85:
        return False, f'low_confidence ({top_score:.3f} < 0.85)'
    if top_label in ('ham', 'spam'):
        return True, f'{top_label}_clear ({top_score:.3f})'
    if top_label == 'scam':
        has_trigger = any(w in text.lower() for w in TRIGGER_WORDS)
        if has_trigger:
            return True, f'scam_with_trigger ({top_score:.3f})'
        else:
            return False, f'scam_no_trigger_url_bias_risk ({top_score:.3f})'
    return False, f'unknown_label ({top_label})'


def save_to_retrain_pool(text, viberta_label, viberta_scores,
                         correct_label, source, confidence,
                         mode='pro', top_label=None, top_score=None):
    if mode == 'standard' and source != 'user_feedback':
        should_save, gate_reason = _should_save_standard_retrain(top_label, top_score, text)
        if not should_save:
            print(f"[RetrainPool][Standard] Bỏ qua: {gate_reason}")
            return
        print(f"[RetrainPool][Standard] Cho phép lưu: {gate_reason}")
    if mode == 'pro':
        AUTO_SOURCES = {'medium_confidence_auto', 'fasttext_fast_path',
                        'fasttext_middle_path', 'groq_low_conf', 'groq_scam_no_trigger'}
        if source in AUTO_SOURCES and viberta_label == correct_label:
            print(f"[RetrainPool][Pro] Bỏ qua auto-correct khớp: {source}")
            return
    try:
        dynamodb.Table('spamshield-retrain-pool').put_item(Item={
            'timestamp'      : Decimal(str(time.time())),
            'email_text'     : text[:2000],
            'viberta_label'  : viberta_label,
            'viberta_scores' : json.loads(json.dumps(viberta_scores), parse_float=Decimal),
            'correct_label'  : correct_label,
            'confidence'     : Decimal(str(round(confidence, 4))),
            'source'         : source,
            'status'         : 'PENDING_RETRAIN',
            'expires_at'     : int(time.time()) + (30 * 24 * 3600),
        })
        print(f"[RetrainPool] Saved: {viberta_label} → {correct_label} ({source})")
    except Exception as e:
        print(f"[RetrainPool] Lỗi lưu: {e}")


def get_viberta_verdict(scores):
    sorted_labels = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    top_label, top_score = sorted_labels[0]
    sec_label, sec_score = sorted_labels[1]
    if top_score >= 0.75:
        return top_label, top_score, 'high_confidence'
    if {top_label, sec_label} == {'spam', 'scam'} and (top_score - sec_score) < 0.20:
        return None, top_score, 'spam_scam_ambiguous'
    if top_score < 0.55:
        return None, top_score, 'low_confidence'
    return top_label, top_score, 'medium_confidence'


def resolve_ambiguous_label(text, viberta_label, viberta_scores, ambiguity_reason):
    groq_label = _verify_external_intelligence(text)
    if groq_label:
        final_label = groq_label
        save_to_retrain_pool(
            text=text, viberta_label=viberta_label, viberta_scores=viberta_scores,
            correct_label=groq_label, source='groq_arbitration',
            confidence=viberta_scores.get(viberta_label or 'ham', 0.0), mode='pro'
        )
    else:
        final_label = viberta_label or 'ham'
        save_to_retrain_pool(
            text=text, viberta_label=viberta_label, viberta_scores=viberta_scores,
            correct_label=viberta_label, source=f'groq_timeout_{ambiguity_reason}',
            confidence=viberta_scores.get(viberta_label or 'ham', 0.0), mode='pro'
        )
    return final_label


def invoke_viberta_safe(payload, timeout_sec=25):
    def _call():
        return sagemaker.invoke_endpoint(
            EndpointName=ENDPOINT_PRO, ContentType='application/json', Body=payload
        )
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_call)
            return future.result(timeout=timeout_sec)
    except concurrent.futures.TimeoutError:
        print(f"[ViBERTa] Hard timeout {timeout_sec}s — endpoint stuck")
        return None
    except Exception as e:
        print(f"[ViBERTa] {type(e).__name__}: {e}")
        return None


# ==========================================
# XỬ LÝ STANDARD MODE (FastText + Groq fallback)
# ==========================================
def process_standard_mode(text, sender_domain):
    print(f"[Standard] sender_domain='{sender_domain}'")
    has_trigger = any(w in text.lower() for w in TRIGGER_WORDS)

    # Cache hit
    if not has_trigger and sender_domain:
        try:
            resp = dynamodb.Table(REP_TABLE_NAME).get_item(Key={'domain': sender_domain})
            if 'Item' in resp and resp['Item'].get('expires_at', 0) > int(time.time()):
                res = resp['Item']['result']
                res['from_cache'] = True
                print(f"[Standard] Cache hit: {sender_domain}")
                return res
        except Exception:
            pass

    # Load FastText
    global _fasttext_model
    if _fasttext_model is None:
        if not os.path.exists(TMP_MODEL_BIN):
            os.makedirs(TMP_MODEL_DIR, exist_ok=True)
            s3.download_file(S3_BUCKET, S3_MODEL_KEY, TMP_TAR_PATH)
            with tarfile.open(TMP_TAR_PATH, 'r:gz') as tar:
                tar.extractall(TMP_MODEL_DIR)
        import fasttext
        _fasttext_model = fasttext.load_model(TMP_MODEL_BIN)

    cleaned_text = advanced_clean_text(text)
    labels, probs = _fasttext_model.predict(cleaned_text, k=3)
    probs_dict = {l.replace('__label__', ''): float(p) for l, p in zip(labels, probs)}
    details = {'ham': probs_dict.get('ham', 0.0), 'spam': probs_dict.get('spam', 0.0), 'scam': probs_dict.get('scam', 0.0)}
    ft_top_label = max(details, key=details.get)
    ft_top_score = details[ft_top_label]

    # Spam keyword boost
    text_lower_std = cleaned_text.lower()
    spam_kw_std = sum(1 for w in SPAM_KEYWORDS if w in text_lower_std)
    if spam_kw_std >= 2:
        details['spam'] = min(1.0, details.get('spam', 0) + spam_kw_std * 0.06)
        details['ham']  = max(0.0, details.get('ham', 0) - spam_kw_std * 0.06)
        ft_top_label = max(details, key=details.get)
        ft_top_score = details[ft_top_label]
        print(f"[Standard] Spam boost: +{spam_kw_std*0.06:.2f}")

    # Fast-path
    if ft_top_score >= 0.85 and not (ft_top_label == 'scam' and not has_trigger):
        print(f"[Standard] Fast-path ({ft_top_label} {ft_top_score:.2f})")
        dns_penalty = check_email_security(sender_domain)
        if dns_penalty > 0:
            details = apply_penalty_with_context(details, [{'type': 'dns_missing', 'weight': dns_penalty}], text)
        final_label = max(details, key=details.get)
        final_score = details[final_label]
        result = {'prediction': final_label, 'probability': final_score, 'details': details,
                  'mode': 'standard', 'dns_penalty_applied': dns_penalty > 0, 'note': 'fasttext_fast_path'}
        save_to_retrain_pool(text=cleaned_text, viberta_label=ft_top_label, viberta_scores=details,
                             correct_label=final_label, source='fasttext_fast_path',
                             confidence=final_score, mode='standard', top_label=ft_top_label, top_score=ft_top_score)
        save_to_reputation_cache(sender_domain, result)
        return result

    # Groq fallback
    needs_groq = ft_top_score < 0.70 or (ft_top_label == 'scam' and not has_trigger)
    if needs_groq:
        reason = 'low_conf' if ft_top_score < 0.70 else 'scam_no_trigger'
        print(f"[Standard] Groq fallback: {reason}")
        groq_label = _verify_external_intelligence(text)
        if groq_label:
            final_prediction = groq_label
        elif ft_top_label == 'scam' and not has_trigger:
            final_prediction = 'spam'
        else:
            final_prediction = ft_top_label
        final_score = ft_top_score if not groq_label else min(max(ft_top_score, 0.72), 0.80)
        dns_penalty = check_email_security(sender_domain)
        if dns_penalty > 0:
            details = apply_penalty_with_context(details, [{'type': 'dns_missing', 'weight': dns_penalty}], text)
        result = {'prediction': final_prediction, 'probability': final_score, 'details': details,
                  'mode': 'standard', 'dns_penalty_applied': dns_penalty > 0, 'note': f'groq_{reason}'}
        save_to_retrain_pool(text=cleaned_text, viberta_label=ft_top_label, viberta_scores=details,
                             correct_label=final_prediction, source=f'groq_{reason}',
                             confidence=final_score, mode='standard', top_label=ft_top_label, top_score=ft_top_score)
        save_to_reputation_cache(sender_domain, result)
        return result

    # Middle path
    dns_penalty = check_email_security(sender_domain)
    if dns_penalty > 0:
        details = apply_penalty_with_context(details, [{'type': 'dns_missing', 'weight': dns_penalty}], text)
    final_prediction = max(details, key=details.get)
    final_score = details[final_prediction]
    result = {'prediction': final_prediction, 'probability': final_score, 'details': details,
              'mode': 'standard', 'dns_penalty_applied': dns_penalty > 0, 'note': 'fasttext_middle_path'}
    save_to_retrain_pool(text=cleaned_text, viberta_label=final_prediction, viberta_scores=details,
                         correct_label=final_prediction, source='fasttext_middle_path',
                         confidence=final_score, mode='standard', top_label=ft_top_label, top_score=ft_top_score)
    save_to_reputation_cache(sender_domain, result)
    return result


# ==========================================
# XỬ LÝ PRO MODE — TEACHER-STUDENT (ViBERTa → Groq)
# ==========================================
def process_pro_mode(text, sender_domain, raw_headers="", attachments={}, qr_images=[]):
    print(f"[Pro] sender_domain='{sender_domain}'")
    highlights      = []
    scores          = {'ham': 0.0, 'spam': 0.0, 'scam': 0.0}
    penalty_signals = []

    # Header forensics
    routing = analyze_header_routing(raw_headers)
    if routing["is_spoofed"]:
        penalty_signals.append({'type': 'header_spoofed', 'weight': 1.0})
        highlights.extend(routing["reason"])

    # Whitelist VIP
    GLOBAL_VIP = ['google.com', 'youtube.com', 'apple.com', 'microsoft.com', 'github.com', 'facebook.com']
    if strict_whitelist_check(sender_domain, GLOBAL_VIP) and check_email_security(sender_domain) == 0 and not routing["is_spoofed"]:
        result = {'prediction': 'ham', 'probability': 1.0, 'details': {'ham': 1.0, 'spam': 0.0, 'scam': 0.0},
                  'mode': 'pro', 'highlights': ['🛡️ Tổ chức Quốc tế'], 'dns_penalty_applied': False}
        save_to_reputation_cache(sender_domain, result)
        return result

    # Magic bytes
    file_pen, file_reasons = deep_inspect_magic_bytes(attachments)
    if file_pen > 0:
        penalty_signals.append({'type': 'malware', 'weight': file_pen})
        highlights.extend(file_reasons)

    # Threat intel
    urls = extract_urls_from_text_and_qr(text, qr_images)
    if check_threat_intel(urls):
        penalty_signals.append({'type': 'threat_intel', 'weight': 1.0})
        highlights.append("💀 URL trong Sổ đen tình báo mạng (Abuse.ch)")

    # =============================================================
    # BƯỚC 1: ViBERTa (Student) — chạy trước
    # =============================================================
    viberta_label = None
    viberta_failed = False
    cleaned_text = advanced_clean_text(text)
    payload = json.dumps({'inputs': cleaned_text})
    response = invoke_viberta_safe(payload, timeout_sec=25)

    if response is None:
        viberta_failed = True
        print("[Pro] ViBERTa không phản hồi")
    else:
        try:
            raw_output = json.loads(response['Body'].read().decode('utf-8'))
            if isinstance(raw_output, list):
                items = raw_output[0] if (len(raw_output) > 0 and isinstance(raw_output[0], list)) else raw_output
                for item in items:
                    if isinstance(item, dict):
                        label = str(item.get('label', '')).lower()
                        score = float(item.get('score', 0.0))
                        if label in ['scam', '2', 'label_2']:   scores['scam'] = score
                        elif label in ['spam', '1', 'label_1']: scores['spam'] = score
                        elif label in ['ham',  '0', 'label_0']: scores['ham']  = score
            if sum(scores.values()) == 0:
                scores['ham'] = 1.0
            viberta_label = max(scores, key=scores.get)
            print(f"[Pro] ViBERTa Student verdict: {viberta_label} (scores: {scores})")
        except Exception as e:
            print(f"[ViBERTa] Parse error: {e}")
            viberta_failed = True

    # DNS penalty
    dns_penalty = check_email_security(sender_domain)
    if dns_penalty > 0:
        penalty_signals.append({'type': 'dns_missing', 'weight': dns_penalty})
        highlights.append("🚨 Thiếu DMARC/SPF")

    # WHOIS
    safe_whois_check(sender_domain, penalty_signals, highlights)

    # Domain impersonation
    vn_vip = ['vietcombank.com.vn', 'vcb.com.vn', 'techcombank.com.vn', 'momo.vn', 'shopee.vn']
    for v in vn_vip:
        if 0 < len(sender_domain) <= len(v) + 2 and sender_domain != v:
            penalty_signals.append({'type': 'domain_impersonation', 'weight': 0.8})
            highlights.append(f"🚨 Tên miền nhái: {v}")
            break

    # Áp dụng penalty
    scores = apply_penalty_with_context(scores, penalty_signals, text)

    # Spam keyword boost
    text_lower_pro = cleaned_text.lower()
    spam_kw_count  = sum(1 for w in SPAM_KEYWORDS if w in text_lower_pro)
    scam_kw_count  = sum(1 for w in SCAM_KEYWORDS if w in text_lower_pro)
    if spam_kw_count >= 2 and scam_kw_count == 0:
        boost = min(0.25, spam_kw_count * 0.06)
        scores['spam'] = min(1.0, scores['spam'] + boost)
        scores['ham']  = max(0.0, scores['ham'] - boost)
        print(f"[Pro] Spam boost: +{boost:.2f}")

    # Cập nhật lại viberta_label sau penalty + boost
    if not viberta_failed:
        viberta_label = max(scores, key=scores.get)

    # =============================================================
    # BƯỚC 2: Groq (Teacher) — LUÔN CHẠY ĐỂ KIỂM TRA LẠI
    # =============================================================
    print("[Pro] Gọi Groq Teacher...")
    groq_label = _verify_external_intelligence(text)

    # =============================================================
    # BƯỚC 3: So sánh Student vs Teacher → Quyết định
    # =============================================================
    if viberta_failed:
        # ViBERTa chết → Groq làm trọng tài
        final_prediction = groq_label or 'ham'
        print(f"[Pro] ViBERTa failed → Groq Teacher quyết định: {final_prediction}")
        result = {
            'prediction': final_prediction, 'probability': 0.65,
            'details': {'ham': 0.0, 'spam': 0.0, 'scam': 0.0, final_prediction: 0.65},
            'mode': 'pro', 'highlights': highlights + ['⚠️ ViBERTa offline — Groq Teacher'],
            'dns_penalty_applied': dns_penalty > 0, 'viberta_status': 'failed'
        }
        save_to_reputation_cache(sender_domain, result)
        return result

    if groq_label is None:
        # Groq timeout → dùng ViBERTa
        final_prediction = viberta_label or 'ham'
        print(f"[Pro] Groq timeout → dùng ViBERTa Student: {final_prediction}")
    elif groq_label == viberta_label:
        # CÙNG Ý KIẾN → lưu retrain pool để củng cố Student
        final_prediction = viberta_label
        print(f"[Pro] ✅ Student=Teacher: {final_prediction} → lưu retrain pool")
        save_to_retrain_pool(
            text=cleaned_text, viberta_label=viberta_label, viberta_scores=scores,
            correct_label=groq_label, source='teacher_agrees',
            confidence=scores.get(viberta_label, 0.0), mode='pro'
        )
    else:
        # KHÁC Ý KIẾN → Teacher (Groq) là đúng → lưu retrain pool để Student học
        final_prediction = groq_label
        print(f"[Pro] 🔄 Student={viberta_label} ≠ Teacher={groq_label} → học từ Teacher")
        save_to_retrain_pool(
            text=cleaned_text, viberta_label=viberta_label, viberta_scores=scores,
            correct_label=groq_label, source='teacher_corrects',
            confidence=scores.get(viberta_label, 0.0), mode='pro'
        )

    # AI insight
    if scores.get('scam', 0) > 0.6 and not any(s['type'] in ('header_spoofed', 'malware', 'threat_intel') for s in penalty_signals):
        highlights.append("🤖 AI phát hiện hành vi thao túng tâm lý ngầm")

    scores[final_prediction] = max(scores.get(final_prediction, 0), 0.6)
    result = {
        'prediction': final_prediction, 'probability': scores[final_prediction],
        'details': scores, 'mode': 'pro', 'highlights': highlights,
        'dns_penalty_applied': dns_penalty > 0
    }

    # LUÔN LƯU REPUTATION CACHE — cả 2 model
    print(f"[Pro] Lưu reputation: {sender_domain} → {final_prediction}")
    save_to_reputation_cache(sender_domain, result)
    return result


# ==========================================
# ĐIỀU PHỐI CHÍNH (HANDLER)
# ==========================================
def lambda_handler(event, context):
    for record in event['Records']:
        job   = json.loads(record['body'])
        table = dynamodb.Table(TABLE_NAME)
        sd = job.get('sender_domain', '')
        print(f"[DEBUG] sender_domain='{sd}' | mode={job.get('mode', 'standard')}")
        try:
            mode = job.get('mode', 'standard')
            hdrs = job.get('raw_headers', '')
            atts = job.get('attachments_b64', {})
            qrs  = job.get('qr_images_b64', [])
            if mode == 'standard':
                result = process_standard_mode(job['text'], sd)
            else:
                result = process_pro_mode(job['text'], sd, hdrs, atts, qrs)
            table.update_item(
                Key={'job_id': job['job_id']},
                UpdateExpression='SET #s = :s, #r = :r',
                ExpressionAttributeNames={'#s': 'status', '#r': 'result'},
                ExpressionAttributeValues={
                    ':s': 'done',
                    ':r': json.loads(json.dumps(result), parse_float=Decimal)
                }
            )
        except Exception as e:
            table.update_item(
                Key={'job_id': job['job_id']},
                UpdateExpression='SET #s = :s, error_msg = :e',
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={':s': 'failed', ':e': str(e)}
            )
