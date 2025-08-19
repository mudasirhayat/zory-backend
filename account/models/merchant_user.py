from django.db import models
from .base_user import CustomUserManager, AbstractCustomUser


class User(AbstractCustomUser):
  phone = models.CharField(max_length=255, null=True, blank=True)

  objects = CustomUserManager()
