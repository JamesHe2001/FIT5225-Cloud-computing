import boto3
import base64
import json
import datetime
import cv2
import numpy as np
import os

print("Starting Lambda function...")

s3 = boto3.client('s3')
original_bucket = "pixtag-original"
thumbnail_bucket = "pixtag-thumbnail666"

def create_thumbnail(image_bytes, size=(200, 200)):
    """创建缩略图"""
    try:
        print(f"Starting thumbnail creation, input size: {len(image_bytes)} bytes")
        
        nparr = np.frombuffer(image_bytes, np.uint8)
        print("Converted to numpy array")
        
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            raise ValueError("Failed to decode image")
        print(f"Decoded image, shape: {img.shape}")
        
        height, width = img.shape[:2]
        print(f"Original image size: {width}x{height}")
        
        scale = min(size[0]/width, size[1]/height)
        new_width = int(width * scale)
        new_height = int(height * scale)
        print(f"New size will be: {new_width}x{new_height}")
        
        resized = cv2.resize(img, (new_width, new_height))
        print("Image resized successfully")
        
        _, buffer = cv2.imencode('.jpg', resized)
        print("Image encoded successfully")
        
        return buffer.tobytes()
    except Exception as e:
        print(f"Error in create_thumbnail: {str(e)}")
        raise

def lambda_handler(event, context):
    """处理 API Gateway 的图片上传请求"""
    print(f"Received event: {json.dumps(event)}")
    
    if event.get("httpMethod") == "POST":
        try:
            print("Processing POST request")
            if event.get("isBase64Encoded", False):
                print("Request contains base64 encoded data")
                try:
                    body = json.loads(event["body"])
                    print("Request body parsed as JSON")
                    if "image" in body:
                        print("Found image field in JSON body")
                        image_bytes = base64.b64decode(body["image"])
                    else:
                        print("No image field found, decoding entire body")
                        image_bytes = base64.b64decode(event["body"])
                except json.JSONDecodeError as je:
                    print(f"JSON decode error: {str(je)}")
                    image_bytes = base64.b64decode(event["body"])
            else:
                print("Request contains raw binary data")
                image_bytes = event["body"].encode("utf-8")
            
            print(f"Decoded image data size: {len(image_bytes)} bytes")
            
            timestamp = datetime.datetime.utcnow().timestamp()
            original_key = f"images/upload_{timestamp}.jpg"
            thumbnail_key = f"thumb_upload_{timestamp}.jpg"
            
            print(f"Original key: {original_key}")
            print(f"Thumbnail key: {thumbnail_key}")
            
            print("Uploading original image to S3...")
            s3.put_object(
                Bucket=original_bucket,
                Key=original_key,
                Body=image_bytes,
                ContentType="image/jpeg"
            )
            print("Original image uploaded successfully")
            
            try:
                print("Starting thumbnail creation process...")
                thumbnail_bytes = create_thumbnail(image_bytes)
                print(f"Thumbnail created, size: {len(thumbnail_bytes)} bytes")
                
                print("Uploading thumbnail to S3...")
                s3.put_object(
                    Bucket=thumbnail_bucket,
                    Key=thumbnail_key,
                    Body=thumbnail_bytes,
                    ContentType="image/jpeg"
                )
                print("Thumbnail uploaded successfully")
                
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        "message": "Image uploaded and thumbnail created",
                        "original_key": original_key,
                        "thumbnail_key": thumbnail_key
                    })
                }
            except Exception as thumb_error:
                print(f"Error creating thumbnail: {str(thumb_error)}")
                print(f"Error type: {type(thumb_error)}")
                import traceback
                print(f"Traceback: {traceback.format_exc()}")
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        "message": "Image uploaded but thumbnail creation failed",
                        "original_key": original_key,
                        "error": str(thumb_error)
                    })
                }
                
        except Exception as e:
            print(f"Error handling upload: {str(e)}")
            print(f"Error type: {type(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            return {
                'statusCode': 500,
                'body': json.dumps({"error": str(e)})
            }

    return {
        'statusCode': 400,
        'body': json.dumps({"error": "Unsupported request method"})
    } 