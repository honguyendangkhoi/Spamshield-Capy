import urllib3
import boto3
import time
import logging

# Thiết lập logging để dễ debug trên CloudWatch
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
# Đảm bảo tên bảng khớp chính xác với bảng bạn đã tạo trong DynamoDB
table = dynamodb.Table('spamshield-threat-intel')

def lambda_handler(event, context):
    http = urllib3.PoolManager()
    
    # URL nguồn từ Abuse.ch (cộng đồng an ninh mạng toàn cầu)
    url = 'https://urlhaus.abuse.ch/downloads/csv_recent/'
    
    try:
        response = http.request('GET', url)
        if response.status != 200:
            logger.error(f"Không thể kết nối tới Abuse.ch, status: {response.status}")
            return {"status": "error", "message": "Failed to fetch feed"}
            
        csv_data = response.data.decode('utf-8')
        lines = csv_data.split('\n')
        
        # [FinOps] Thiết lập TTL: Dữ liệu tự động xóa sau 7 ngày (604800 giây)
        # Việc xóa tự động này là MIỄN PHÍ trên AWS DynamoDB
        expire_time = int(time.time()) + 604800
        
        count = 0
        # Batch write giúp giảm chi phí request và tăng tốc độ ghi
        with table.batch_writer() as batch:
            for line in lines:
                # Bỏ qua dòng chú thích hoặc dòng trống
                if line.startswith('#') or not line.strip(): 
                    continue
                
                parts = line.split(',')
                # Cấu trúc file CSV của URLhaus: id, dateadded, url, url_status, ...
                if len(parts) > 2:
                    malicious_url = parts[2].replace('"', '')
                    
                    batch.put_item(Item={
                        'entity': malicious_url,
                        'type': 'URL',
                        'status': 'MALICIOUS',
                        'expires_at': expire_time  # Quan trọng cho tính năng tự xóa TTL
                    })
                    count += 1
        
        logger.info(f"Đã đồng bộ thành công {count} bản ghi vào bảng threat-intel.")
        return {"status": "success", "synced_records": count, "ttl_enabled": True}

    except Exception as e:
        logger.error(f"Lỗi đồng bộ dữ liệu: {str(e)}")
        return {"status": "error", "message": str(e)}u
