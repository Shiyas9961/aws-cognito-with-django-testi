import base64
import hashlib
import hmac
import boto3
from botocore.exceptions import ClientError
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import LoginSerializer, RegisterSerializer, RefreshTokenSerializer
from .utils import get_secret_hash
from django.conf import settings

def get_secret_hash(username, client_id, client_secret):
    message = username + client_id
    dig = hmac.new(client_secret.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).digest()
    return base64.b64encode(dig).decode()

class LoginView(APIView):

    def post(self, request):
        
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            client = boto3.client('cognito-idp', region_name=settings.COGNITO_REGION)

            try:
                response = client.initiate_auth(
                    AuthFlow='USER_PASSWORD_AUTH',
                    AuthParameters={
                        'USERNAME': username,
                        'PASSWORD': password,
                        'SECRET_HASH' : get_secret_hash(username, settings.COGNITO_APP_CLIENT_ID, settings.COGNITO_APP_CLIENT_SECRET)
                    },
                    ClientId=settings.COGNITO_APP_CLIENT_ID
                )
                tokens = response['AuthenticationResult']
                request.session['username'] = username
                return Response(tokens, status=status.HTTP_200_OK)
            except ClientError as e:
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserRegisterView(APIView) :

    def post(self, request) :

        data = request.data
        data['role'] = data.get('role', 'user')
        data['name'] = data.get('name', request.data['username'])
        serializer = RegisterSerializer(data=data)

        if serializer.is_valid() :

            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            email = serializer.validated_data['email']
            role = serializer.validated_data['role']
            name = serializer.validated_data['name']

            client_id = settings.COGNITO_APP_CLIENT_ID
            client_secret = settings.COGNITO_APP_CLIENT_SECRET
            secret_hash = get_secret_hash(username, client_id, client_secret)

            client = boto3.client('cognito-idp', region_name = settings.COGNITO_REGION)
            
            try:
                response = client.sign_up(
                    ClientId = settings.COGNITO_APP_CLIENT_ID,
                    SecretHash = secret_hash,
                    Username = username,
                    Password = password,
                    UserAttributes = [
                        {
                            'Name' : 'email', 'Value' : email,
                        },
                        {
                            'Name' : 'name', 'Value' : name
                        },
                        {
                            'Name' : 'custom:role', 'Value' : role
                        }
                    ]
                )
            except client.exceptions.UsernameExistsException as e:
                return Response({"error": "This username already exists"}, status=status.HTTP_400_BAD_REQUEST)
            except client.exceptions.InvalidPasswordException as e:
                return Response({"error": "The password provided is invalid"}, status=status.HTTP_400_BAD_REQUEST)
            except client.exceptions.UserLambdaValidationException as e:
                return Response({"error": "User cannot be created"}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)
        else :
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RefreshTokenView (APIView) :

    def post(self, request) :

        serializer = RefreshTokenSerializer(data=request.data)

        if serializer.is_valid() :

            refresh_token = serializer.validated_data['refresh_token']

            client_id = settings.COGNITO_APP_CLIENT_ID
            client_secret = settings.COGNITO_APP_CLIENT_SECRET
            username = request.session.get('username')
            client = boto3.client('cognito-idp', settings.COGNITO_REGION)

            try :
                response = client.initiate_auth(AuthFlow = 'REFRESH_TOKEN_AUTH', AuthParameters = {'REFRESH_TOKEN' : refresh_token, 'SECRET_HASH' : get_secret_hash(username, client_id, client_secret)},ClientId = client_id)
                
                return Response({
                    "access_token" : response['AuthenticationResult']['AccessToken'],
                    "id_token" : response['AuthenticationResult']['IdToken'],
                    "expires_in" : response['AuthenticationResult']['ExpiresIn'],
                    "token_type" : response['AuthenticationResult']['TokenType']
                }, status=status.HTTP_200_OK)
            
            except client.exceptions.NotAuthorizedException :
                return Response({"error" : "refresh_token is invalid or expired. "}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e :
                return Response({"error" : str(e)}, status=status.HTTP_400_BAD_REQUEST)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)