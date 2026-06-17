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

        if not text:
            return _resp(400, {'error': 'text is required'})

        # Cắt text xuống 1500 ký tự — inference nhanh hơn ~40%, đủ để phân tích spam
        text = text[:1500]

        job_id = str(uuid.uuid4())
        ttl    = int(time.time()) + 3600  # tự xóa sau 1h

        # Ghi job vào DynamoDB với status=pending
        table = dynamodb.Table(TABLE_NAME)
        table.put_item(Item={
            'job_id': job_id,
            'status': 'pending',
            'mode':   mode,
            'ttl':    ttl,
        })

        # Đẩy job vào SQS
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
