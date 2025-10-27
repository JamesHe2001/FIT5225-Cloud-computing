import json
import boto3

s3_client = boto3.client('s3')

def lambda_handler(event, context):
    try:
        print("Received event:", json.dumps(event))  
        
        
        bucket = event.get("bucket")
        key = event.get("key")
        
        
        if not bucket or not key:
            
            body = event.get('body')
            if body:
                
                if isinstance(body, str):
                    try:
                        body_json = json.loads(body)
                        bucket = body_json.get('bucket')
                        key = body_json.get('key')
                    except json.JSONDecodeError:
                        print("Failed to parse body as JSON:", body)
                elif isinstance(body, dict):
                    bucket = body.get('bucket')
                    key = body.get('key')
        
        print(f"Extracted bucket: {bucket}, key: {key}")  
        
        if not bucket or not key:
            return {
                "statusCode": 400,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps("Missing 'bucket' or 'key'")
            }

        s3_client.delete_object(Bucket=bucket, Key=key)

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps(f"Successfully deleted {key} from {bucket}")
        }

    except Exception as e:
        print("Error:", str(e))  
        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps(f"Error: {str(e)}")
        }