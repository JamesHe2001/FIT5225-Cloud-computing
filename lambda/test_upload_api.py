import requests
import json
import os
import login
import random

def read_auth_tokens():
    with open('auth_tokens.txt', 'r') as f:
        tokens = {}
        for line in f:
            if ': ' in line:
                key, value = line.strip().split(': ', 1)
                tokens[key] = value
        return tokens

def get_random_image():
    test_images_dir = 'test_images'
    image_files = [f for f in os.listdir(test_images_dir) if f.lower().endswith(('.jpg', '.jpeg', '.png'))]
    return os.path.join(test_images_dir, random.choice(image_files))

def test_upload_with_presigned_url():
    API_BASE_URL = "https://pzsjhrvhz8.execute-api.us-east-1.amazonaws.com/dev"
    login.login()
    tokens = read_auth_tokens()
    id_token = tokens.get('ID Token', '')

    headers = {
        'Authorization': f"Bearer {id_token}"
    }

    print("1 request upload url...")
    response = requests.get(f"{API_BASE_URL}/get-upload-url", headers=headers)
    upload_info = response.json()
    upload_url = upload_info["upload_url"]
    s3_key = upload_info["s3_key"]
    print("✔️ get upload url success:", s3_key)

    image_path = get_random_image()
    print(f"2 upload image: {image_path}")
    with open(image_path, 'rb') as f:
        image_data = f.read()

    put_response = requests.put(
        upload_url,
        data=image_data,
        headers={'Content-Type': 'image/jpeg'}
    )

    if put_response.status_code == 200:
        print(" image upload success")
        print(f"S3 Key: {s3_key}")
    else:
        print(" upload failed:", put_response.status_code)
        print(put_response.text)

if __name__ == "__main__":
    test_upload_with_presigned_url()
