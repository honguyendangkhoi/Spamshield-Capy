import json
import boto3
from decimal import Decimal

dynamodb   = boto3.resource('dynamodb')
TABLE_NAME = 'spamshield-jobs'

def decimal_default(obj):
    if isinstance(obj, Decimal):
        # Trả về int nếu là số nguyên, ngược lại trả về float
        return int(obj) if obj % 1 == 0 else float(obj)
    raise TypeError

def lambda_handler(event, context):
    try:
        params = event.get('queryStringParameters') or {}
        job_id = params.get('job_id', '').strip()

        if not job_id:
            return _resp(400, {'error': 'job_id is required'})

        table = dynamodb.Table(TABLE_NAME)
        item  = table.get_item(Key={'job_id': job_id}).get('Item')

        if not item:
            return _resp(404, {'error': 'job not found'})

        status = item['status']

        if status == 'done':
            return _resp(200, {'status': 'done', 'result': item.get('result', {})})

        if status == 'failed':
            return _resp(200, {'status': 'failed', 'error': item.get('error_msg', 'Unknown error')})

        # pending hoặc processing — client tiếp tục poll
        return _resp(200, {'status': status})

    except Exception as e:
        return _resp(500, {'error': str(e)})


def _resp(code, body):
    return {
        'statusCode': code,
        'headers': {
            'Content-Type':                'application/json',
            'Access-Control-Allow-Origin': '*',
        },
        # Gọi helper decimal_default để ép kiểu ngay khi dumps
        'body': json.dumps(body, default=decimal_default),
    }
