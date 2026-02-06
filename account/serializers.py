from django.core import exceptions
from django.core.exceptions import ValidationError
from rest_framework import serializers
from django.core.validators import RegexValidator
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str, smart_str
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.password_validation import validate_password
from rest_framework.generics import get_object_or_404
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import User, DashboardUser, UserSubscription
from core.models import Role
from core.utils.helpers import translate_text

from rest_framework import serializers
from google.auth.transport import requests
from google.oauth2 import id_token
from django.conf import settings


def get_highest_role(user):
    """
    Determine the highest role of the user across all businesses.
    Role hierarchy: OWNER > ADMIN > VIEWER
    """
    roles = user.roles.values_list("role", flat=True)
    role_hierarchy = {"OWNER": 3, "ADMIN": 2, "VIEWER": 1}

    if user.is_superuser:
        return "SUPERADMIN"

    highest_role = None
    for role in roles:
        if (
                highest_role is None
                or role_hierarchy[role] > role_hierarchy[highest_role]
        ):
            highest_role = role

    return highest_role


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)

token = self.get_token(self.user)
token.update({
    "email": self.user.email,
    "user_id": self.user.id
})
        token["highest_role"] = get_highest_role(self.user)
        token["english_name"] = self.user.name_english
        token["arabic_name"] = self.user.name_arabic
        token["is_super_user"] = self.user.is_superuser

        return {
            "refresh": str(token),
            "access": str(token.access_token),
        }


class CustomTokenObtainPairDashboardSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        token = self.get_token(self.user)
        token["email"] = self.user.email
        token["user_id"] = self.user.id
        token["english_name"] = self.user.name_english
        token["arabic_name"] = self.user.name_arabic

        return {
            "refresh": str(token),
            "access": str(token.access_token),
        }


class ChangePasswordSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ("password", "confirm_password")
        extra_kwargs = {"password": {"write_only": True}}

    def validate(self, data):
        data = super().validate(data)
        try:
            if not data.get("password") == data.get("confirm_password"):
                raise serializers.ValidationError({"error": "Password doesn't match"})
            validate_password(password=data.get("password"))
            return data
        except exceptions.ValidationError as e:
            errors = {"password": list(e.messages)}
            raise serializers.ValidationError(errors)

    def save(self):
        user = self.instance
        user.set_password(self.validated_data.get("password"))
        user.save()
        return user


class BaseUserSerializer(serializers.ModelSerializer):
    """
    Base serializer with common fields and validation logic.
    """
    confirm_password = serializers.CharField(max_length=60, write_only=True)

    class Meta:
        abstract = True
        fields = (
            "id",
            "email",
            "name_arabic",
            "name_english",
            "password",
            "confirm_password",
            "profile_picture_url",
        )
        extra_kwargs = {
            "id": {"read_only": True},
            "password": {"write_only": True},
        }

    def save(self):
        del self.validated_data["confirm_password"]

        user = User(**self.validated_data)
        user.set_password(self.validated_data.get("password"))
        user.save()
        return user

    def validate(self, data):
        data = super().validate(data)
        try:
            if not data.get("password") == data.get("confirm_password"):
                raise serializers.ValidationError({"error": "Password doesn't match"})
            validate_password(password=data.get("password"))
            return data
        except exceptions.ValidationError as e:
            errors = {"password": list(e.messages)}
            raise serializers.ValidationError(errors)


class UserSerializer(BaseUserSerializer):
    """
  Serializer for regular users.
  """

    class Meta(BaseUserSerializer.Meta):
        model = User
        fields = BaseUserSerializer.Meta.fields + ("phone",)  # Add phone field


class DashboardUserSerializer(BaseUserSerializer):
    """
  Serializer for dashboard users.
  """

    class Meta(BaseUserSerializer.Meta):
        model = DashboardUser

    def save(self):
        del self.validated_data["confirm_password"]

        user = DashboardUser(**self.validated_data)
        user.set_password(self.validated_data.get("password"))
        user.save()
        return user


class ProfileUpdateSerializer(serializers.ModelSerializer):
    phone = serializers.CharField(
        required=True,
        validators=[
            RegexValidator(
                regex=r"^\+?1?\d{9,15}$",
                message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.",
            )
        ],
    )
    name_arabic = serializers.CharField(required=True, allow_blank=False)
    name_english = serializers.CharField(required=True, allow_blank=False)
    profile_picture_url = serializers.URLField(required=False)

    class Meta:
        model = User
        fields = ["name_arabic", "name_english", "phone", "profile_picture_url"]


class DashboardProfileUpdateSerializer(serializers.ModelSerializer):
    name_arabic = serializers.CharField(required=True, allow_blank=False)
    name_english = serializers.CharField(required=True, allow_blank=False)
    profile_picture_url = serializers.URLField(required=False)

    class Meta:
        model = DashboardUser
        fields = ["name_arabic", "name_english", "profile_picture_url"]

    def validate(self, data):
        name_ar = data.get("name_arabic")
        name_en = data.get("name_english")

        if not name_ar and not name_en:
            raise serializers.ValidationError("Either name_english or name_arabic must be provided.")

        unified_name = name_ar or name_en
        data["name_arabic"] = unified_name
        data["name_english"] = unified_name

        return data


class InActivateUserSerializer(serializers.ModelSerializer):
    is_active = serializers.BooleanField(default=False)

    class Meta:
        model = User
        fields = ("is_active",)


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        fields = ["email"]

    def validate_email(self, value):
        user_model = self.context.get('user_model')
        user = get_object_or_404(user_model, email=value)
        if not user:
            raise serializers.ValidationError("User with this email does not exist.")

        if isinstance(user, DashboardUser) and user.google_auth_enabled:
            raise serializers.ValidationError("Google users are not allowed to reset your password")
        return value


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    confirm_password = serializers.CharField(
        min_length=6, max_length=68, write_only=True
    )
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ["password", "confirm_password", "token", "uidb64"]

    def validate(self, attrs):
        try:
            password = attrs.get("password")
            confirm_password = attrs.get("confirm_password")
            token = attrs.get("token")
            uidb64 = attrs.get("uidb64")

            if password != confirm_password:
                raise serializers.ValidationError(
                    {"confirm_password": "Passwords do not match."}
                )

            id = force_str(urlsafe_base64_decode(uidb64))

            # Extract user model from serializer context
            user_model = self.context.get('user_model')
            user = get_object_or_404(user_model, id=id)

            if user and isinstance(user, DashboardUser) and user.google_auth_enabled:
                raise serializers.ValidationError("Cannot reset password for google logins")

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed("The reset link is invalid or expired.", 401)

            user.set_password(password)
            user.save()

            return user
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found.", 404)
        except AuthenticationFailed:
            raise AuthenticationFailed("The reset link is invalid or expired.", 401)


class BusinessRoleSerializer(serializers.ModelSerializer):
    user = serializers.CharField(source="member.name_english")
    email = serializers.EmailField(source="member.email")
    business = serializers.CharField(source="business.name_english")
    status = serializers.BooleanField(source="business.active_status")
    role = serializers.CharField()

    class Meta:
        model = Role
        fields = ["user", "email", "business", "status", "role"]


class GoogleAuthSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate_token(self, token):
        try:
            # Verify the token with Google
            idinfo = id_token.verify_oauth2_token(
                token,
                requests.Request(),
                settings.GOOGLE_CLIENT_ID
            )

            # Check if token is from correct issuer
            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                raise serializers.ValidationError('Invalid token issuer')

            return idinfo

        except ValueError as e:
            raise serializers.ValidationError(f'Invalid token: {str(e)}')

    def create(self, validated_data):
        idinfo = validated_data['token']

        email = idinfo.get('email')
        name = idinfo.get('name', '')
        picture = idinfo.get('picture', '')

        translate_dict = translate_text(name)
        name_english = translate_dict["english"]
        name_arabic = translate_dict["arabic"]

        if not email:
            raise serializers.ValidationError('Email not provided by Google')

        # Check if user exists
        user, created = DashboardUser.objects.get_or_create(
            email=email,
            defaults={
                'name_english': name_english,
                'name_arabic': name_arabic,
                'profile_picture_url': picture,
                'is_active': True,
                'google_auth_enabled': True
            }
        )

        if user and not created and not user.google_auth_enabled:
            raise ValidationError("Already signed in using email")

        # Track if user was created for response
        user._created = created

        # Update user info if not created (existing user)
        if not created:
            if not user.name_english and name:
                user.name_english = name
            if not user.profile_picture_url and picture:
                user.profile_picture_url = picture
            user.save()

        return user


class InvoiceSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    plan = serializers.CharField(source="plan.name", read_only=True)
    amount = serializers.DecimalField(source="plan.price", max_digits=10, decimal_places=2, read_only=True)
    date = serializers.SerializerMethodField()

    class Meta:
        model = UserSubscription
        fields = ["invoice_number", "status", "plan", "date", "amount"]

    def get_status(self, obj):
        mapping = {
            "Completed": "paid",
            "Decline": "cancel",
            "In Progress": "in progress",
        }
        return mapping.get(obj.status, obj.status)

    def get_date(self, obj):
        return obj.subscription_start.strftime("%b %d, %Y")
