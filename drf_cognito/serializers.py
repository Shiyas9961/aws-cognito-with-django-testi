from rest_framework import serializers

class LoginSerializer(serializers.Serializer):

    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)

class RegisterSerializer(serializers.Serializer) :

    username = serializers.CharField(required = True, max_length = 100)
    password = serializers.CharField(required = True, write_only = True, max_length = 100)
    email = serializers.EmailField(required = True)
    role = serializers.CharField(max_length = 50)
    name = serializers.CharField(max_length=150, required = True)

class RefreshTokenSerializer(serializers.Serializer) :

    refresh_token = serializers.CharField(required = True)
