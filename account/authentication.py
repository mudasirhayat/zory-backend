from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
from rest_framework.exceptions import AuthenticationFailed

from .models.dashboard_user import DashboardUser
from django.contrib.auth import get_user_model

class CustomJWTAuthentication(JWTAuthentication):
  def authenticate(self, request):
    # First perform the regular JWT authentication
    result = super().authenticate(request)

    if result is None:
      return None

    user, token = result
    user_type = token.payload.get('user_type', 'regular')

    try:
      jti = token.payload.get("jti")
      if BlacklistedToken.objects.filter(token__jti=jti).exists():
        raise AuthenticationFailed("Token is blacklisted")
    except Exception:
      raise AuthenticationFailed(
        {
          "detail": "Given token not valid",
          "messages": "Token is blacklisted",
        }
      )

    # Assigning user to Django request as we are using default Auth model (User)
    request.user = user
    request.user_type = user_type

    return user, token

  def get_user(self, validated_token):
    """Get user based on user_type in token."""
    user_id = validated_token['user_id']
    user_type = validated_token.get('user_type', 'regular')

    if user_type == 'dashboard':
      return DashboardUser.objects.get(id=user_id)
    else:
      User = get_user_model()
      return User.objects.get(id=user_id)
