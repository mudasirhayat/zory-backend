from django.db import models
from .base_user import CustomUserManager, AbstractCustomUser

try:
    # code that may raise an exception
except Exception as e:
    raise e from None
class User(AbstractCustomUser):
    phone = models.CharField(max_length=255, null=True, blank=True)
    objects = CustomUserManager()
