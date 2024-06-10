# authentication.py

import requests
from jose import jwt, jwk
from rest_framework import authentication, exceptions
from django.conf import settings

class CognitoUser:
    def __init__(self, claims):
        self.claims = claims
        self.is_authenticated = True
        self.username = claims.get('username')
        self.email = claims.get('email')
        self.name = claims.get('name')
        self.role = claims.get('custom:role')  # Custom attribute

class CognitoAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        id_token = request.headers.get('Authorization')

        if not id_token:
            return None

        try:
            id_token = id_token.split(' ')[1]  # Extract the token from "Bearer <token>"
        except IndexError:
            raise exceptions.AuthenticationFailed('Invalid token header. No credentials provided.')

        try:
            claims = self.decode_verify_jwt(id_token)
        except jwt.JWTError as e:
            raise exceptions.AuthenticationFailed('Invalid token.')

        user = CognitoUser(claims)
        return (user, id_token)

    def decode_verify_jwt(self, token):
        region = settings.COGNITO_REGION
        user_pool_id = settings.COGNITO_USER_POOL_ID
        app_client_id = settings.COGNITO_APP_CLIENT_ID

        keys_url = f'https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json'
        response = requests.get(keys_url)
        keys = response.json()['keys']

        headers = jwt.get_unverified_headers(token)
        kid = headers.get('kid')
        if not kid:
            raise exceptions.AuthenticationFailed('No "kid" found in token headers.')

        key = next(key for key in keys if key['kid'] == kid)
        public_key = jwk.construct(key)

        try:
            claims = jwt.decode(token, public_key, algorithms=['RS256'], audience=app_client_id)
            return claims
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('Token is expired.')
        except jwt.JWTClaimsError:
            raise exceptions.AuthenticationFailed('Incorrect claims. Please check the audience and issuer.')
        except Exception as e:
            raise exceptions.AuthenticationFailed(f'Error decoding token: {str(e)}')