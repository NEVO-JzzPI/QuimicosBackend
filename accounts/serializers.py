from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Serializer usado por el endpoint POST /token/.
    Extiende el serializer normal de SimpleJWT para "meter" datos del
    usuario dentro del access token (como claims), asi el frontend no
    necesita hacer una segunda llamada tipo /me/ para saber quien
    inicio sesion: le basta con decodificar el token que ya recibio.
    """

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Claims extra: viajan dentro del JWT (firmados, no secretos).
        # El frontend los lee decodificando el access token en base64.
        token['name'] = user.name
        token['first_lastname'] = user.first_lastname
        token['type'] = user.type  # 'administrador' o 'empleado'

        return token

class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    re_password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['email', 'password', 're_password', 'name', 'first_lastname']

    def validate_password(self, password):
        try:
            validate_password(password)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(list(exc.messages))
        return password

    def validate(self, data):
        if data['password'] != data['re_password']:
            raise serializers.ValidationError({'re_password': 'Passwords do not match.'})
        return data

    def create(self, validated_data):
        validated_data.pop('re_password')
        return User.objects.create_user(**validated_data)
