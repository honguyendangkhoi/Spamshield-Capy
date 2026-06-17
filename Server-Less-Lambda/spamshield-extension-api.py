import json
import boto3
import re
import os
import unicodedata

# Khởi tạo client gọi SageMaker
sm_runtime = boto3.client('sagemaker-runtime', region_name='ap-southeast-1')
ENDPOINT_NAME = os.environ.get('ENDPOINT_NAME', 'spam-detection-endpoint-final')

# Từ khóa lừa đảo mạnh - chỉ giữ những từ thực sự nguy hiểm
SPAM_KEYWORDS = [
    r'trung thuong', r'nhan thuong',
    r'rut tien', r'chuyen khoan',
    r'dau tu', r'loi nhuan',
    r'mien phi', r'click ngay', r'bam vao',
    r'xac minh tai khoan',
    r'otp', r'ma xac nhan',
    r'tang qua', r'qua tang',
    r'khuyen mai', r'uu dai',
    r'flash sale', r'hot deal', r'giam gia soc',
    r'vay tien', r'cho vay', r'lai suat thap',
    r'tien ao',
    r'lam giau', r'thu nhap cao',
]

def preprocess_for_blazingtext(text):
    """
    BlazingText chỉ ăn ASCII lowercase, không dấu, không ký tự đặc biệt.
    Bắt buộc phải clean trước khi gửi SageMaker.
    """
    # 1. Chuẩn hóa unicode → tách dấu tiếng Việt ra khỏi chữ cái
    text = unicodedata.normalize('NFD', text)
    # 2. Xóa toàn bộ dấu (category Mn = Mark, Nonspacing)
    text = ''.join(c for c in text if unicodedata.category(c) != 'Mn')
    # 3. Lowercase
    text = text.lower()
    # 4. Xóa mọi ký tự không phải chữ/số/space
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    # 5. Gộp khoảng trắng thừa
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def get_highlights(text):
    """Bóc tách từ khóa đáng ngờ để Extension bôi đỏ - dùng text GỐC (có dấu)"""
    highlights = []

    # Bắt link URL
    urls = re.findall(r'https?://\S+|www\.\S+', text)
    highlights.extend(urls)

    # Bắt số tiền
    money = re.findall(
        r'\d+[\.,]?\d*\s*(?:trieu|trieu dong|nghin|nghin dong|k|d\b|vnd)',
        text, re.IGNORECASE
    )
    highlights.extend(money)

    # Bắt từ khóa kêu gọi
    promo_pattern = (
        r'\b(khuyen mai|uu dai|giam gia|sale|tang qua|qua tang|mien phi'
        r'|free ship|freeship|flash sale|hot deal|combo'
        r'|trung thuong|boc tham|rut tham|qua may man)\b'
    )
    promos = re.findall(promo_pattern, text, re.IGNORECASE)
    highlights.extend(promos)

    return list(set(highlights))

def check_spam_keywords(text):
    """
    Rule-based check trên text ĐÃ được preprocess (không dấu, lowercase).
    Trả về (is_spam, score, matched_keywords)
    """
    matched = []
    for pattern in SPAM_KEYWORDS:
        if re.search(pattern, text, re.IGNORECASE):
            matched.append(pattern)

    has_url = bool(re.search(r'https?://\S+|www\.\S+', text))

    # URL + ít nhất 2 keyword → chắc chắn spam
    if has_url and len(matched) >= 2:
        score = min(0.95 + len(matched) * 0.01, 0.99)
        return True, score, matched

    # Ít nhất 3 keyword (không cần URL) → spam
    if len(matched) >= 3:
        score = min(0.90 + len(matched) * 0.01, 0.99)
        return True, score, matched

    return False, 0.0, matched

def lambda_handler(event, context):
    try:
        # Xử lý OPTIONS preflight (CORS)
        if event.get('httpMethod') == 'OPTIONS':
            return {
                'statusCode': 200,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type',
                    'Access-Control-Allow-Methods': 'OPTIONS,POST'
                },
                'body': ''
            }

        # 1. Hứng data từ Extension
        body = json.loads(event.get('body', '{}'))
        raw_text = body.get('text', '')

        print(f"Input text (100 ký tự đầu): {raw_text[:100]}")

        if not raw_text or not raw_text.strip():
            return {
                'statusCode': 400,
                'headers': {'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Email trống!'})
            }

        # 2. Highlights dùng text gốc (có dấu để bôi đúng từ)
        highlights = get_highlights(raw_text)

        # 3. Preprocess text để dùng cho rule-based và SageMaker
        clean_text = preprocess_for_blazingtext(raw_text)
        print(f"Text sau preprocess: {clean_text[:100]}")

        # 4. Rule-based check trên clean text
        is_spam_by_rule, rule_score, matched_keywords = check_spam_keywords(clean_text)
        print(f"Rule-based: is_spam={is_spam_by_rule}, score={rule_score}, matched={matched_keywords}")

        CORS_HEADERS = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Methods': 'OPTIONS,POST'
        }

        if is_spam_by_rule:
            print("=> Override: SPAM by rule-based")
            return {
                'statusCode': 200,
                'headers': CORS_HEADERS,
                'body': json.dumps({
                    'status': 'spam',
                    'probability': rule_score,
                    'highlights': highlights
                })
            }

        # 5. Không có dấu hiệu rõ → hỏi SageMaker
        if not clean_text:
            # Sau khi clean còn rỗng (email toàn ký tự lạ)
            return {
                'statusCode': 200,
                'headers': CORS_HEADERS,
                'body': json.dumps({
                    'status': 'ham',
                    'probability': 0.05,
                    'highlights': highlights
                })
            }

        payload = json.dumps({"instances": [clean_text]})
        print(f"Payload gửi SageMaker: {payload[:200]}")

        response = sm_runtime.invoke_endpoint(
            EndpointName=ENDPOINT_NAME,
            ContentType='application/json',
            Body=payload
        )

        result = json.loads(response['Body'].read().decode('utf-8'))
        print(f"SageMaker raw result: {json.dumps(result)}")

        label = result[0]['label'][0].replace('__label__', '')
        prob  = result[0]['prob'][0]

        # 6. Chuẩn hóa về spam_probability
        # BlazingText trả prob của LABEL NÓ CHỌN
        # → label=ham, prob=0.93 nghĩa là 93% chắc HAM = chỉ 7% spam
        if label == 'ham':
            spam_probability = 1.0 - prob
        else:
            spam_probability = prob

        print(f"AI: label={label}, prob={prob}, spam_probability={spam_probability:.3f}")

        # 7. Nâng cảnh báo nếu AI bảo ham nhưng có ≥2 keyword khả nghi
        if label == 'ham' and len(matched_keywords) >= 2:
            spam_probability = max(spam_probability, 0.65)
            print(f"=> Nâng cảnh báo: ham + {len(matched_keywords)} keywords")

        # 8. Ngưỡng quyết định cuối
        final_status = 'spam' if spam_probability >= 0.60 else 'ham'
        print(f"=> Kết quả cuối: {final_status} ({spam_probability:.3f})")

        return {
            'statusCode': 200,
            'headers': CORS_HEADERS,
            'body': json.dumps({
                'status': final_status,
                'probability': round(spam_probability, 4),
                'highlights': highlights
            })
        }

    except Exception as e:
        print(f"LAMBDA ERROR: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }
