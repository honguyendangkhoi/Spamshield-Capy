import json
import uuid
import boto3
import time

dynamodb = boto3.resource('dynamodb')
sqs = boto3.client('sqs')

TABLE_NAME = 'spamshield-jobs'
QUEUE_URL  = 'https://sqs.ap-southeast-1.amazonaws.com/992409270804/spamshield-queue'

def lambda_handler(event, context):
    try:
        body = json.loads(event.get('body', '{}'))
        text = body.get('text', '').strip()
        mode = body.get('mode', 'standard')

        # Nếu là feedback, không yêu cầu text
        if mode != 'feedback' and not text:
            return _resp(400, {'error': 'text is required'})

        text = text[:1500] if text else ''

        job_id = str(uuid.uuid4())
        ttl    = int(time.time()) + 3600

        table = dynamodb.Table(TABLE_NAME)

        # ============================================================
        # THÊM MỚI: XỬ LÝ FEEDBACK
        # ============================================================
        if mode == 'feedback':
            feedback_payload = {
                'job_id': job_id,
                'text': text[:2000] if text else '',
                'mode': 'feedback',
                'original_prediction': body.get('original_prediction', ''),
                'correct_label': body.get('correct_label', ''),
                'source': body.get('source', 'user_feedback'),
                'confidence': body.get('confidence', 1.0),
                'sender_domain': body.get('sender_domain', ''),
            }
            sqs.send_message(
                QueueUrl=QUEUE_URL,
                MessageBody=json.dumps(feedback_payload)
            )
            table.put_item(Item={
                'job_id': job_id,
                'status': 'pending',
                'mode': 'feedback',
                'ttl': ttl,
            })
            return _resp(200, {'job_id': job_id, 'message': 'feedback submitted'})

        # Nếu không phải feedback, xử lý như cũ
        table.put_item(Item={
            'job_id': job_id,
            'status': 'pending',
            'mode':   mode,
            'ttl':    ttl,
        })

        sqs.send_message(
            QueueUrl    = QUEUE_URL,
            MessageBody = json.dumps({'job_id': job_id, 'text': text, 'mode': mode}),
        )

        return _resp(200, {'job_id': job_id})

    except Exception as e:
        return _resp(500, {'error': str(e)})


def _resp(code, body):
    return {
        'statusCode': code,
        'headers': {
            'Content-Type':                'application/json',
            'Access-Control-Allow-Origin': '*',
        },
        'body': json.dumps(body),
    }
