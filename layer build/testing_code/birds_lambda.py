import json
import boto3
import cv2
import numpy as np
from ultralytics import YOLO
import os
import tempfile
import time
import torch

s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('bird_detections')

def download_file_from_s3(bucket, key):
    """Download a file from S3 into a temporary directory"""
    try:
        print(f"Attempting to download file from S3: bucket={bucket}, key={key}")
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            s3_client.download_fileobj(bucket, key, tmp_file)
            return tmp_file.name
    except Exception as e:
        print(f"Error downloading file: {str(e)}")
        return None

def read_image_from_temp(temp_path):
    """Read image from a temporary file"""
    try:
        print(f"Attempting to read image: {temp_path}")
        img = cv2.imread(temp_path)
        if img is None:
            raise Exception("Failed to read the image file")
        return img
    except Exception as e:
        print(f"Error reading image: {str(e)}")
        return None

def detect_birds(image, confidence_threshold=0.6):
    """Detect birds in the image using YOLO model"""
    try:
        print("Loading YOLO model...")
        torch.serialization.add_safe_globals(['ultralytics.nn.tasks.DetectionModel'])
        
        model = YOLO("model.pt")
        
        print("Running detection...")
        results = model(image)[0]
        
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
        
        print(f"Detection finished, found {len(detections)} objects")
        return detections
    except Exception as e:
        print(f"Error during detection: {str(e)}")
        return []

def save_to_dynamodb(image_url, thumbnail_url, detections):
    """Save detection results to DynamoDB"""
    try:
        print(f"Attempting to save results to DynamoDB: {image_url}")
        item = {
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
    """Lambda function entry point"""
    try:
        print("Lambda function started...")
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = event['Records'][0]['s3']['object']['key']
        
        print(f"Processing image: bucket={bucket}, key={key}")
        
        image_url = f"s3://{bucket}/{key}"
        
        temp_path = download_file_from_s3(bucket, key)
        if not temp_path:
            return {
                'statusCode': 500,
                'body': json.dumps('Error downloading file from S3')
            }
        
        image = read_image_from_temp(temp_path)
        if image is None:
            return {
                'statusCode': 500,
                'body': json.dumps('Error reading image')
            }
        
        detections = detect_birds(image)
        
        save_success = save_to_dynamodb(image_url, "", detections)
        
        try:
            os.remove(temp_path)
        except Exception as e:
            print(f"Error cleaning up temporary file: {str(e)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Processing completed successfully',
                'detections': detections
            })
        }
        
    except Exception as e:
        print(f"Error during processing: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }