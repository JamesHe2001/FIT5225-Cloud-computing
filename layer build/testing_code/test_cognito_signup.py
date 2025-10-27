import boto3
import json
import random
import string
import hmac
import base64
import hashlib
from botocore.exceptions import ClientError

def generate_random_username():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

def generate_random_password():
    lowercase = ''.join(random.choices(string.ascii_lowercase, k=3))
    uppercase = ''.join(random.choices(string.ascii_uppercase, k=3))
    digits = ''.join(random.choices(string.digits, k=2))
    special = ''.join(random.choices('!@#$%^&*', k=2))
    password = lowercase + uppercase + digits + special
    password_list = list(password)
    random.shuffle(password_list)
    return ''.join(password_list)

def generate_random_name():
    first_names = ['Alex', 'Sam', 'Chris', 'Jordan', 'Taylor', 'Morgan', 'Casey', 'Jamie']
    last_names = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis']
    return random.choice(first_names), random.choice(last_names)

def get_secret_hash(username, client_id, client_secret):
    msg = username + client_id
    dig = hmac.new(str(client_secret).encode('utf-8'),
                   msg=str(msg).encode('utf-8'),
                   digestmod=hashlib.sha256).digest()
    return base64.b64encode(dig).decode()

def test_signup():
    client = boto3.client('cognito-idp', region_name='us-east-1')
    
    USER_POOL_ID = 'us-east-1_g4SvG2N1E'
    CLIENT_ID = '4quucr17sofk8c874jlhm29g0o'
    CLIENT_SECRET = 'bim9cvkkua3443kam6vrr5jar1umu8p0rmdi6b8c520r9knm42r'
    
    test_username = generate_random_username()
    test_email = "nauxuswatchout@gmail.com"  # Use your actual email
    test_password = generate_random_password()
    first_name, last_name = generate_random_name()
    
    print(f"\nStarting signup test...")
    print(f"Test username: {test_username}")
    print(f"Test email: {test_email}")
    print(f"Test password: {test_password}")
    print(f"First name: {first_name}")
    print(f"Last name: {last_name}")
    print("\nPlease save this information! You will need it to verify the email and log in.")
    
    try:
        secret_hash = get_secret_hash(test_username, CLIENT_ID, CLIENT_SECRET)
        
        response = client.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=secret_hash,
            Username=test_username,
            Password=test_password,
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': test_email
                },
                {
                    'Name': 'given_name',
                    'Value': first_name
                },
                {
                    'Name': 'family_name',
                    'Value': last_name
                }
            ]
        )
        
        print("\nSignup successful!")
        print(f"User UUID: {response['UserSub']}")
        print("Please check your email inbox at nauxuswatchout@gmail.com. You should receive a verification code.")
        print("After you receive the code, you can log in using the following credentials:")
        print(f"Username: {test_username}")
        print(f"Password: {test_password}")
        
    except ClientError as e:
        print(f"\nSignup failed: {str(e)}")
        if 'UsernameExistsException' in str(e):
            print("That username is already taken.")
        elif 'InvalidPasswordException' in str(e):
            print("The generated password did not meet the policy requirements.")
        else:
            print("An unexpected error occurred. Please check your configuration and AWS permissions.")

if __name__ == "__main__":
    test_signup()