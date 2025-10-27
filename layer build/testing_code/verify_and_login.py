import boto3
import hmac
import base64
import hashlib
from botocore.exceptions import ClientError

def get_secret_hash(username, client_id, client_secret):
    msg = username + client_id
    dig = hmac.new(str(client_secret).encode('utf-8'),
                   msg=str(msg).encode('utf-8'),
                   digestmod=hashlib.sha256).digest()
    return base64.b64encode(dig).decode()

def verify_and_login():
    client = boto3.client('cognito-idp', region_name='us-east-1')
    
    CLIENT_ID = '4quucr17sofk8c874jlhm29g0o'
    CLIENT_SECRET = 'bim9cvkkua3443kam6vrr5jar1umu8p0rmdi6b8c520r9knm42r'
    
    # Get user input
    username = input("Enter username: ")
    verification_code = input("Enter verification code: ")
    password = input("Enter password: ")
    
    try:
        # First, confirm email/verification code
        secret_hash = get_secret_hash(username, CLIENT_ID, CLIENT_SECRET)
        confirm_response = client.confirm_sign_up(
            ClientId=CLIENT_ID,
            SecretHash=secret_hash,
            Username=username,
            ConfirmationCode=verification_code
        )
        print("\nEmail verification successful!")
        
        # Then try to log in
        try:
            auth_response = client.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                ClientId=CLIENT_ID,
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password,
                    'SECRET_HASH': secret_hash
                }
            )
            
            print("\nLogin successful!")
            print("Access Token:", auth_response['AuthenticationResult']['AccessToken'][:20] + "...")
            print("ID Token:", auth_response['AuthenticationResult']['IdToken'][:20] + "...")
            print("Refresh Token:", auth_response['AuthenticationResult']['RefreshToken'][:20] + "...")
            
            # Optionally save tokens to file
            with open('auth_tokens.txt', 'w') as f:
                f.write(f"Access Token: {auth_response['AuthenticationResult']['AccessToken']}\n")
                f.write(f"ID Token: {auth_response['AuthenticationResult']['IdToken']}\n")
                f.write(f"Refresh Token: {auth_response['AuthenticationResult']['RefreshToken']}\n")
            print("\nTokens saved to auth_tokens.txt")
            
        except ClientError as e:
            if 'NotAuthorizedException' in str(e):
                print("Login failed: incorrect username or password")
            else:
                print(f"Error during login: {str(e)}")
            
    except ClientError as e:
        if 'ExpiredCodeException' in str(e):
            print("The verification code has expired. Please sign up again to get a new one.")
        elif 'CodeMismatchException' in str(e):
            print("Incorrect verification code. Please check and try again.")
        elif 'AliasExistsException' in str(e):
            print("This email is already verified. Attempting direct login...")
            # If the email is already verified, attempt login directly
            try:
                secret_hash = get_secret_hash(username, CLIENT_ID, CLIENT_SECRET)
                auth_response = client.initiate_auth(
                    AuthFlow='USER_PASSWORD_AUTH',
                    ClientId=CLIENT_ID,
                    AuthParameters={
                        'USERNAME': username,
                        'PASSWORD': password,
                        'SECRET_HASH': secret_hash
                    }
                )
                
                print("\nLogin successful!")
                print("Access Token:", auth_response['AuthenticationResult']['AccessToken'][:20] + "...")
                print("ID Token:", auth_response['AuthenticationResult']['IdToken'][:20] + "...")
                print("Refresh Token:", auth_response['AuthenticationResult']['RefreshToken'][:20] + "...")
                
                # Optionally save tokens to file
                with open('auth_tokens.txt', 'w') as f:
                    f.write(f"Access Token: {auth_response['AuthenticationResult']['AccessToken']}\n")
                    f.write(f"ID Token: {auth_response['AuthenticationResult']['IdToken']}\n")
                    f.write(f"Refresh Token: {auth_response['AuthenticationResult']['RefreshToken']}\n")
                print("\nTokens saved to auth_tokens.txt")
                
            except ClientError as e:
                print(f"Error during login: {str(e)}")
        else:
            print(f"Error during verification: {str(e)}")

if __name__ == "__main__":
    verify_and_login()