import json, re, os, boto3, tempfile, tarfile

model = None

def load_model():
    global model
    if model is not None:
        return model

    import fasttext

    s3     = boto3.client('s3')
    bucket = os.environ['MODEL_BUCKET']   # spam-detection-doannhom
    key    = os.environ['MODEL_KEY']      # standard/output/fasttext/model_standard.tar.gz

    print("[SpamShield] Downloading model from S3...")
    tmp_tar = tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False)
    s3.download_fileobj(bucket, key, tmp_tar)
    tmp_tar.close()

    # Giải nén — tìm file .bin bên trong
    extract_dir = tempfile.mkdtemp()
    with tarfile.open(tmp_tar.name, 'r:gz') as tar:
        tar.extractall(extract_dir)

    bin_path = None
    for root, dirs, files in os.walk(extract_dir):
        for f in files:
            if f.endswith('.bin'):
                bin_path = os.path.join(root, f)
                break

    if not bin_path:
        raise FileNotFoundError("Không tìm thấy file .bin trong tar.gz")

    print(f"[SpamShield] Loading model from {bin_path}...")
    model = fasttext.load_model(bin_path)
    print("[SpamShield] Model ready!")
    return model

def lambda_handler(event, context):
    body = event.get('body', '{}')
    if isinstance(body, str):
        body = json.loads(body)

    text = body.get('text', '')
    if not text:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'text is required'})
        }

    m = load_model()
    labels, probs = m.predict(text.lower(), k=3)

    label_clean = [l.replace('__label__', '') for l in labels]
    result = {
        'prediction': label_clean[0],
        'probabilities': {l: round(float(p), 4) for l, p in zip(label_clean, probs)}
    }
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps(result)
    }
