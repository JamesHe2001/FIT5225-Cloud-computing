import os
# Set environment variables before importing any other packages
os.environ['MPLBACKEND'] = 'Agg'  # Use a non-interactive backend
os.environ['MATPLOTLIB_USE'] = 'Agg'
os.environ['QT_QPA_PLATFORM'] = 'offscreen'

import json
import boto3
import cv2
import numpy as np
from ultralytics import YOLO
import tempfile
import time

# Initialize AWS service clients
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('bird_detections')

def download_file_from_s3(bucket, key):
    """Download a file from S3 into a temporary directory"""
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            s3_client.download_fileobj(bucket, key, tmp_file)
            return tmp_file.name
    except Exception as e:
        print(f"Error downloading file: {str(e)}")
        return None

def detect_birds(image_path, confidence_threshold=0.6):
    """Detect birds in an image using the YOLO model"""
    try:
        # Load YOLO model
        model = YOLO("model.pt")
        
        # Read the image
        img = cv2.imread(image_path)
        if img is None:
            raise Exception("Failed to read image")
        
        # Run detection with visualization disabled
        results = model(img, verbose=False, conf=confidence_threshold, show=False, save=False)[0]
        
        # Process detection results
        detections = []
        for result in results.boxes.data:
            x1, y1, x2, y2, conf, cls = result
            if conf > confidence_threshold:
                class_name = model.names[int(cls)]
                detections.append({
                    'class': class_name,
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
            'image_id': image_url.split('/')[-1],  # Use file name as primary key
            'image_url': image_url,
            'thumbnail_url': thumbnail_url,
            'detections': detections,
            'timestamp': int(time.time())
        }
        table.put_item(Item=item)
        return True
    except Exception as e:
        print(f"Error saving to database: {str(e)}")
        return False

def lambda_handler(event, context):
    """AWS Lambda function entry point"""
    try:
        # Get S3 information from event
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = event['Records'][0]['s3']['object']['key']
        
        # Construct S3 URL
        image_url = f"s3://{bucket}/{key}"
        
        # Download the image
        temp_path = download_file_from_s3(bucket, key)
        if not temp_path:
            return {
                'statusCode': 500,
                'body': json.dumps('Error downloading file from S3')
            }
        
        # Run detection
        detections = detect_birds(temp_path)
        
        # Remove temporary file
        os.remove(temp_path)
        
        # Save results to DynamoDB
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
            'body': json.dumps(f'Error: {str(e)}')
        }