"""
SpamShield AI — AWS Lambda Function
=====================================
Logic: Check Endpoint → Tạo nếu chưa có → Gọi inference → Trả kết quả
"""

import json
import boto3
import logging
import time
from botocore.config import Config
from botocore.exceptions import ClientError

# ============================================================
# CONFIG
# ============================================================
REGION        = 'ap-southeast-1'
ROLE          = 'arn:aws:iam::992409270804:role/SageMakerExecutionRole'
ENDPOINT_NAME = 'spam-detection-endpoint-final'
MODEL_NAME    = ENDPOINT_NAME
CONFIG_NAME   = ENDPOINT_NAME
S3_MODEL_URI  = 's3://spam-detection-doannhom/models/videberta/model.tar.gz'

# Container PyTorch 1.13 cho SageMaker (ap-southeast-1)
CONTAINER = '763104351884.dkr.ecr.ap-southeast-1.amazonaws.com/pytorch-inference:1.13.1-gpu-py39-cu117-ubuntu20.04-sagemaker'

INSTANCE_TYPE = 'ml.g4dn.xlarge'   # GPU nhỏ nhất — PhoBERT cần GPU để inference nhanh
                                    # Đổi sang ml.m5.large nếu muốn rẻ hơn (CPU, chậm hơn)

BOTO_CONFIG = Config(
    connect_timeout=15,
    read_timeout=120,
    retries={'max_attempts': 3, 'mode': 'adaptive'}
)

LABEL_NAMES = ['ham', 'spam', 'scam']

# ============================================================
# LOGGING
# ============================================================
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ============================================================
# HELPERS
# ============================================================
def get_sm_client():
    return boto3.client('sagemaker', region_name=REGION, config=BOTO_CONFIG)

def get_runtime_client():
    return boto3.client('sagemaker-runtime', region_name=REGION, config=BOTO_CONFIG)

def get_endpoint_status(sm):
    """Trả về status string hoặc None nếu endpoint không tồn tại."""
    try:
        resp = sm.describe_endpoint(EndpointName=ENDPOINT_NAME)
        return resp['EndpointStatus']   # InService | Creating | Failed | ...
    except ClientError as e:
        if e.response['Error']['Code'] == 'ValidationException':
            return None
        raise

def create_endpoint(sm):
    """Tạo Model + EndpointConfig + Endpoint từ S3."""
    logger.info('Tạo SageMaker Model...')
    try:
        sm.create_model(
            ModelName=MODEL_NAME,
            PrimaryContainer={
                'Image': CONTAINER,
                'ModelDataUrl': S3_MODEL_URI,
                'Environment': {
                    'SAGEMAKER_PROGRAM': 'inference.py',
                    'SAGEMAKER_SUBMIT_DIRECTORY': '/opt/ml/model/code',
                }
            },
            ExecutionRoleArn=ROLE
        )
    except ClientError as e:
        if 'already exists' not in str(e):
            raise

    logger.info('Tạo EndpointConfig...')
    try:
        sm.create_endpoint_config(
            EndpointConfigName=CONFIG_NAME,
            ProductionVariants=[{
                'VariantName':          'AllTraffic',
                'ModelName':            MODEL_NAME,
                'InitialInstanceCount': 1,
                'InstanceType':         INSTANCE_TYPE
            }]
        )
    except ClientError as e:
        if 'already exists' not in str(e):
            raise

    logger.info('Tạo Endpoint...')
    try:
        sm.create_endpoint(
            EndpointName=ENDPOINT_NAME,
            EndpointConfigName=CONFIG_NAME
        )
    except ClientError as e:
        if 'already exists' not in str(e):
            raise

    logger.info(f'Endpoint đang khởi động: {ENDPOINT_NAME}')

def call_inference(text: str) -> dict:
    """Gọi SageMaker Endpoint, parse kết quả PhoBERT."""
    runtime = get_runtime_client()
    payload = json.dumps({'inputs': text})

    resp = runtime.invoke_endpoint(
        EndpointName=ENDPOINT_NAME,
        ContentType='application/json',
        Body=payload
    )
    result = json.loads(resp['Body'].read().decode('utf-8'))

    # inference.py trả về: {"prediction": "spam", "probabilities": {"ham":0.1,"spam":0.8,"scam":0.1}}
    prediction   = result.get('prediction', 'ham')
    probs        = result.get('probabilities', {})
    probability  = probs.get(prediction, 0.0)

    # Highlights đơn giản: từ khoá nghi ngờ (mở rộng sau nếu cần)
    highlights = _extract_highlights(text, prediction)

    return {
        'status':      prediction,
        'probability': round(probability, 4),
        'highlights':  highlights,
        'all_probs':   probs
    }

def _extract_highlights(text: str, prediction: str) -> list:
    """Trích từ khoá đáng ngờ để hiển thị trên Extension."""
    if prediction == 'ham':
        return []
    import re
    keywords = []
    if re.search(r'https?://\S+', text):
        keywords.append('🔗 URL đáng ngờ')
    if re.search(r'(0\d{9,10})', text):
        keywords.append('📞 Số điện thoại lạ')
    scam_words = ['trúng thưởng', 'chuyển khoản', 'miễn phí', 'khẩn cấp',
                  'xác minh', 'tài khoản bị khóa', 'click', 'nhấp vào']
    for w in scam_words:
        if w.lower() in text.lower():
            keywords.append(w)
    return keywords[:5]   # Tối đa 5 highlights

# ============================================================
# CORS HEADERS
# ============================================================
CORS_HEADERS = {
    'Content-Type':                'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
}

def respond(status_code: int, body: dict):
    return {
        'statusCode': status_code,
        'headers':    CORS_HEADERS,
        'body':       json.dumps(body, ensure_ascii=False)
    }

# ============================================================
# LAMBDA HANDLER
# ============================================================
def lambda_handler(event, context):
    # OPTIONS preflight (CORS)
    if event.get('httpMethod') == 'OPTIONS':
        return respond(200, {})

    # Parse body
    try:
        body = json.loads(event.get('body') or '{}')
        text = body.get('text', '').strip()
    except Exception:
        return respond(400, {'error': 'Body không hợp lệ, cần JSON với key "text"'})

    if not text:
        return respond(400, {'error': 'Thiếu nội dung email (key "text")'})

    sm = get_sm_client()
    status = get_endpoint_status(sm)
    logger.info(f'Endpoint status hiện tại: {status}')

    # --- CASE 1: Endpoint chưa tồn tại → tạo mới ---
    if status is None:
        try:
            create_endpoint(sm)
        except Exception as e:
            logger.error(f'Lỗi tạo endpoint: {e}')
            return respond(500, {'error': f'Không thể tạo endpoint: {str(e)}'})
        return respond(202, {
            'status':       'cold_start',
            'message':      'AI đang khởi động lần đầu (~90 giây). Vui lòng thử lại sau.',
            'retry_after':  90
        })

    # --- CASE 2: Đang tạo / updating ---
    if status in ('Creating', 'Updating', 'SystemUpdating', 'RollingBack'):
        return respond(202, {
            'status':      'warming',
            'message':     f'AI đang khởi động ({status}). Vui lòng thử lại sau.',
            'retry_after': 30
        })

    # --- CASE 3: Failed ---
    if status == 'Failed':
        # Xóa tài nguyên cũ để lần sau tạo lại sạch
        logger.warning('Endpoint Failed — xóa để tạo lại lần sau')
        for fn, kwargs in [
            (sm.delete_endpoint,        {'EndpointName':       ENDPOINT_NAME}),
            (sm.delete_endpoint_config, {'EndpointConfigName': CONFIG_NAME}),
            (sm.delete_model,           {'ModelName':          MODEL_NAME}),
        ]:
            try:
                fn(**kwargs)
            except Exception:
                pass
        return respond(503, {
            'status':  'failed',
            'message': 'Endpoint bị lỗi, đã reset. Thử lại để khởi động lại AI.',
            'retry_after': 10
        })

    # --- CASE 4: InService → gọi inference ---
    if status == 'InService':
        try:
            result = call_inference(text)
            logger.info(f'Kết quả: {result}')
            return respond(200, result)
        except Exception as e:
            logger.error(f'Lỗi inference: {e}')
            return respond(500, {'error': f'Lỗi phân tích: {str(e)}'})

    # Trạng thái không xác định
    return respond(503, {
        'status':  'unknown',
        'message': f'Trạng thái lạ: {status}. Thử lại sau.',
        'retry_after': 15
    })
