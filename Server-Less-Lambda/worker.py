import urllib3
import boto3

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('spamshield-threat-intel')

def lambda_handler(event, context):
    http = urllib3.PoolManager()
    # Tải danh sách URL độc hại mới nhất (Cập nhật 5p một lần bởi cộng đồng TG)
    response = http.request('GET', 'https://urlhaus.abuse.ch/downloads/csv_recent/')
    
    count = 0
    if response.status == 200:
        csv_data = response.data.decode('utf-8')
        lines = csv_data.split('\n')
        
        with table.batch_writer() as batch:
            for line in lines:
                if line.startswith('#') or not line.strip(): continue
                parts = line.split(',')
                if len(parts) > 2:
                    malicious_url = parts[2].replace('"', '')
                    batch.put_item(Item={
                        'entity': malicious_url,
                        'type': 'URL',
                        'status': 'MALICIOUS'
                    })
                    count += 1
    return {"status": "success", "synced_records": count}
