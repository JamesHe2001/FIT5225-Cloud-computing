# app.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import boto3
import hmac
import base64
import hashlib
import os
from botocore.exceptions import ClientError
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


CLIENT_ID = os.getenv("COGNITO_CLIENT_ID", "REDACTED_CLIENT_ID")
CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET", "REDACTED_CLIENT_SECRET")
REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

class LoginRequest(BaseModel):
    username: str
    password: str

def setup_aws_credentials():
    os.environ["AWS_ACCESS_KEY_ID"] = os.getenv("AWS_ACCESS_KEY_ID", "REDACTED")
    os.environ["AWS_SECRET_ACCESS_KEY"] = os.getenv("AWS_SECRET_ACCESS_KEY", "REDACTED")
    os.environ["AWS_SESSION_TOKEN"] = os.getenv("AWS_SESSION_TOKEN", "REDACTED")
    os.environ["AWS_DEFAULT_REGION"] = REGION

def get_secret_hash(username, client_id, client_secret):
    msg = username + client_id
    dig = hmac.new(client_secret.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).digest()
    return base64.b64encode(dig).decode()

def login_cognito(username, password):
    setup_aws_credentials()
    client = boto3.client('cognito-idp', region_name=REGION)

    auth_response = client.initiate_auth(
        ClientId=CLIENT_ID,
        AuthFlow='USER_PASSWORD_AUTH',
        AuthParameters={
            'USERNAME': username,
            'PASSWORD': password,
            'SECRET_HASH': get_secret_hash(username, CLIENT_ID, CLIENT_SECRET)
        }
    )
    return auth_response['AuthenticationResult']

@app.post("/login")
def login_api(request: LoginRequest):
    try:
        auth_result = login_cognito(request.username, request.password)
        return {
            "access_token": auth_result['AccessToken'],
            "id_token": auth_result['IdToken'],
            "refresh_token": auth_result['RefreshToken']
        }
    except ClientError as e:
        error_message = str(e)
        if 'NotAuthorizedException' in error_message:
            raise HTTPException(status_code=401, detail="Incorrect username or password")
        elif 'UserNotConfirmedException' in error_message:
            raise HTTPException(status_code=403, detail="User email address not verified")
        else:
            raise HTTPException(status_code=500, detail="Login failed, please check the configuration and parameters")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
