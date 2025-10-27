import json
import boto3
import cv2
import numpy as np
import os
import tempfile
import time
import onnxruntime

# Initialize AWS service clients
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('bird_detections')

# Bird class mapping
CLASSES = {
    0: 'Crow',
    1: 'Kingfisher',
    2: 'Myna',
    3: 'Owl',
    4: 'Peacock',
    5: 'Pigeon',
    6: 'Sparrow'
}

def download_file_from_s3(bucket, key):
    """Download file from S3 to a temporary directory"""
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            s3_client.download_fileobj(bucket, key, tmp_file)
            return tmp_file.name
    except Exception as e:
        print(f"Error downloading file: {str(e)}")
        return None

def preprocess_image(img, input_size=(640, 640)):
    """Preprocess the image before inference"""
    # Resize image while maintaining aspect ratio
    h, w = img.shape[:2]
    ratio = min(input_size[0] / w, input_size[1] / h)
    new_w, new_h = int(w * ratio), int(h * ratio)
    resized = cv2.resize(img, (new_w, new_h))
    
    # Create padded image
    padded = np.zeros((input_size[0], input_size[1], 3), dtype=np.uint8)
    dx = (input_size[1] - new_w) // 2
    dy = (input_size[0] - new_h) // 2
    padded[dy:dy+new_h, dx:dx+new_w] = resized
    
    # Normalize and reorder dimensions
    x = padded.astype(np.float32) / 255.0
    x = np.transpose(x, (2, 0, 1))  # HWC → CHW
    x = np.expand_dims(x, axis=0)   # Add batch dimension
    return x, (ratio, dx, dy)

def detect_birds(image_path, confidence_threshold=0.25):
    """Detect birds using YOLO ONNX model"""
    try:
        # Read image
        img = cv2.imread(image_path)
        if img is None:
            raise Exception("Failed to read image")

        # Preprocess image
        x, (ratio, dx, dy) = preprocess_image(img)
        
        # Load ONNX model
        session = onnxruntime.InferenceSession("model.onnx", providers=['CPUExecutionProvider'])
        
        # Get input name
        input_name = session.get_inputs()[0].name
        
        # Run inference
        outputs = session.run(None, {input_name: x})
        
        # Extract predictions
        predictions = outputs[0][0]  # Shape: [300, 6]
        
        # Filter predictions by confidence threshold
        mask = predictions[:, 4] > confidence_threshold
        valid_preds = predictions[mask]
        
        # Build detection result list
        detections = []
        for pred in valid_preds:
            x1, y1, x2, y2, conf, cls_id = pred
            cls_id = int(cls_id)
            
            # Adjust coordinates based on padding and scaling
            x1 = (x1 - dx) / ratio
            y1 = (y1 - dy) / ratio
            x2 = (x2 - dx) / ratio
            y2 = (y2 - dy) / ratio
            
            detections.append({
                'class': CLASSES[cls_id],
                'confidence': float(conf),
                'bbox': [float(x) for x in [x1, y1, x2, y2]]
            })
        
        return detections
    except Exception as e:
        print(f"Error during detection: {str(e)}")
        return []

def save_to_dynamodb(image_url, thumbnail_url, detections):
    """Save detection results to DynamoDB"""
    try:
        item = {
            'image_id': image_url.split('/')[-1],  # Use filename as primary key
            'image_url': image_url,
            'thumbnail_url': thumbnail_url,
            'detections': detections,
            'timestamp': int(time.time())
        }
        table.put_item(Item=item)
        return True
    except Exception as e:
        print(f"Error saving to DynamoDB: {str(e)}")
        return False

def process_s3_event(event):
    """Handle S3 trigger event"""
    try:
        # Extract S3 information from event
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = event['Records'][0]['s3']['object']['key']
        
        # Build S3 URL
        image_url = f"s3://{bucket}/{key}"
        
        # Download image
        temp_path = download_file_from_s3(bucket, key)
        if not temp_path:
            return {
                'statusCode': 500,
                'body': json.dumps('Error downloading file from S3')
            }
        
        # Run detection
        detections = detect_birds(temp_path)
        
        # Clean up temporary file
        os.remove(temp_path)
        
        # Save detection results
        save_success = save_to_dynamodb(image_url, "", detections)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Processing completed successfully',
                'detections': detections
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error processing S3 event: {str(e)}')
        }

def process_test_event(event):
    """Handle non-S3 test event"""
    try:
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Test event received successfully',
                'event': event,
                'info': 'This is a test event. To test bird detection, please use an S3 trigger or provide a valid S3 event format.'
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error processing test event: {str(e)}')
        }

def lambda_handler(event, context):
    """AWS Lambda entry point"""
    try:
        # Check if the event is triggered by S3
        if (
            'Records' in event
            and len(event['Records']) > 0
            and 'eventSource' in event['Records'][0]
            and event['Records'][0]['eventSource'] == 'aws:s3'
        ):
            return process_s3_event(event)
        else:
            return process_test_event(event)
            
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }