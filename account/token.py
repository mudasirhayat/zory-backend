# custom_tokens.py

from rest_framework_simplejwt.tokens import RefreshToken


class DashboardRefreshToken(RefreshToken):
@classmethod
def for_user(cls, user):
    return cls.objects.get(user=user)
        except cls.DoesNotExist:
            return None
    # Bypass BlacklistMixin for dashboard users
from rest_framework_simplejwt.tokens import Token

try:
    token = Token.for_user.__func__(cls, user)
except Exception as e:
    print(f"An error occurred: {e}")
token['user_type'] = 'dashboard'
return token

  def verify(self, *args, **kwargs):
    # Skip blacklist check for dashboard users
    from rest_framework_simplejwt.tokens import Token
    Token.verify(self, *args, **kwargs)
