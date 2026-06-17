import json
import boto3

sagemaker     = boto3.client('sagemaker', region_name='ap-southeast-1')
lambda_client = boto3.client('lambda', region_name='ap-southeast-1')

WORKER_FUNCTION_NAME = 'worker'

def safe_delete(fn, resource_type, name):
    try:
        fn()
        return 'deleted'
    except Exception as e:
        code = getattr(e, 'response', {}).get('Error', {}).get('Code', '')
        if code in ('ValidationException', 'ResourceNotFound'):
            return 'not_found'
        return f'error: {str(e)}'

def lambda_handler(event, context):
    results = []

    # 1. Quét và dọn dẹp SageMaker
    try:
        endpoints = sagemaker.list_endpoints().get('Endpoints', [])
        for ep in endpoints:
            ep_name = ep['EndpointName']
            status = safe_delete(lambda: sagemaker.delete_endpoint(EndpointName=ep_name), 'endpoint', ep_name)
            results.append({'endpoint': f"SageMaker: {ep_name}", 'status': status})

        configs = sagemaker.list_endpoint_configs().get('EndpointConfigs', [])
        for cfg in configs:
            safe_delete(lambda: sagemaker.delete_endpoint_config(EndpointConfigName=cfg['EndpointConfigName']), 'config', cfg['EndpointConfigName'])

        models = sagemaker.list_models().get('Models', [])
        for mdl in models:
            safe_delete(lambda: sagemaker.delete_model(ModelName=mdl['ModelName']), 'model', mdl['ModelName'])
    except Exception as e:
        print(f"Lỗi quét SageMaker: {e}")

    # 2. Đóng băng hàm Worker
    try:
        lambda_client.put_function_concurrency(
            FunctionName=WORKER_FUNCTION_NAME,
            ReservedConcurrentExecutions=0
        )
        results.append({'endpoint': f"Lambda ({WORKER_FUNCTION_NAME})", 'status': 'deleted'}) # Gửi 'deleted' để UI hiện tick xanh
    except Exception as e:
        code = getattr(e, 'response', {}).get('Error', {}).get('Code', '')
        if code == 'ResourceNotFoundException':
            results.append({'endpoint': f"Lambda ({WORKER_FUNCTION_NAME})", 'status': 'not_found'})
        else:
            results.append({'endpoint': f"Lambda ({WORKER_FUNCTION_NAME})", 'status': f'error: {str(e)}'})

    if not results:
        results.append({'endpoint': 'Hệ thống AI', 'status': 'not_found'})

    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
        },
        'body': json.dumps({
            'message': 'Shutdown complete',
            'results': results,
        }),
    }
