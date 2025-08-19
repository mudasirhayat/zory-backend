# custom_tokens.py

from rest_framework_simplejwt.tokens import RefreshToken


class DashboardRefreshToken(RefreshToken):
  @classmethod
  def for_user(cls, user):
    # Bypass BlacklistMixin for dashboard users
    from rest_framework_simplejwt.tokens import Token
    token = Token.for_user.__func__(cls, user)
    token['user_type'] = 'dashboard'
    return token

  def verify(self, *args, **kwargs):
    # Skip blacklist check for dashboard users
    from rest_framework_simplejwt.tokens import Token
    Token.verify(self, *args, **kwargs)
