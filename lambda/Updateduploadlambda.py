import boto3
import json
import base64
import time
import datetime

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')

ORIGINAL_BUCKET = "pixtag-original"
THUMBNAIL_BUCKET = "pixtag-thumbnail666"
DDB_TABLE_NAME = "PixTag-Metadata"
table = dynamodb.Table(DDB_TABLE_NAME)

def write_tags_to_dynamodb(image_key, tags):
    filename = image_key.split('/')[-1]
    timestamp = int(time.time())
    image_url = f"https://{ORIGINAL_BUCKET}.s3.amazonaws.com/{image_key}"
    thumbnail_url = f"https://{THUMBNAIL_BUCKET}.s3.amazonaws.com/thumb_{filename}"

    for tag, count in tags.items():
        item = {
            'image_id': filename,
            'tag': tag,
            'full_image_url': image_url,
            'thumbnail_url': thumbnail_url,
            'count': count,
            'timestamp': timestamp
        }
        table.put_item(Item=item)

def lambda_handler(event, context):
    if event.get("httpMethod") == "POST":
        try:
            body = json.loads(event["body"])
            image_b64 = body.get("image")
            if not image_b64:
                return {'statusCode': 400, 'body': "Missing image field"}

            image_bytes = base64.b64decode(image_b64)
            timestamp = datetime.datetime.utcnow().timestamp()
            key = f"images/upload_{timestamp}.jpg"

            s3.put_object(
                Bucket=ORIGINAL_BUCKET,
                Key=key,
                Body=image_bytes,
                ContentType="image/jpeg"
            )

            tags = {
                "Crow": 2,
                "Pigeon": 1
            }

            write_tags_to_dynamodb(key, tags)

            return {
                'statusCode': 200,
                'body': json.dumps({
                    "message": "Upload success and metadata saved",
                    "image_key": key,
                    "tags": tags
                })
            }

        except Exception as e:
            return {
                'statusCode': 500,
                'body': f"Error: {str(e)}"
            }

    return {
        'statusCode': 400,
        'body': json.dumps({"error": "Only POST supported"})
    }
