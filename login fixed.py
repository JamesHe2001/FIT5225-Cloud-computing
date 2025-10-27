@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            # fallback for HTML form submission
            username = request.form.get('username')
            password = request.form.get('password')

        setup_aws_credentials()
        client = boto3.client('cognito-idp', region_name=AWS_REGION)

        try:
            auth_response = client.initiate_auth(
                ClientId=CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password,
                    'SECRET_HASH': get_secret_hash(username)
                }
            )

            # Create or update local user
            user = User.query.filter_by(username=username).first()
            if not user:
                user = User(username=username, password='[COGNITO_MANAGED]')
                db.session.add(user)
                db.session.commit()

            login_user(user)

            session['access_token'] = auth_response['AuthenticationResult']['AccessToken']
            session['id_token'] = auth_response['AuthenticationResult']['IdToken']
            session['refresh_token'] = auth_response['AuthenticationResult']['RefreshToken']

            return jsonify({
                'status': 'success',
                'message': 'Login successful',
                'tokens': {
                    'access_token': auth_response['AuthenticationResult']['AccessToken'],
                    'id_token': auth_response['AuthenticationResult']['IdToken'],
                    'refresh_token': auth_response['AuthenticationResult']['RefreshToken']
                }
            })

        except ClientError as e:
            error_message = str(e)
            app.logger.error(f'Login error for user {username}: {error_message}')

            if 'NotAuthorizedException' in error_message:
                message = "Invalid username or password"
            elif 'UserNotConfirmedException' in error_message:
                message = "Email not verified"
            else:
                message = "Login failed, please try again later"
            return jsonify({'status': 'error', 'message': message}), 400

    return render_template('login.html')
