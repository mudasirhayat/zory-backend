from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)


class CustomUserManager(BaseUserManager):
  def create_user(self, email, password=None, **extra_fields):
    """
    Creates and saves a User with the given email and password.
    """
    if not email:
      raise ValueError("The email address is required")
    if not password:
      raise ValueError("Password is required")

email = self.normalize_email(email)
user = self.model(email=email, **extra_fields)
user.set_password(password)
    user.save(using=self._db)
    return user

  def create_superuser(self, email, password=None, **extra_fields):
    """
    Creates and saves a superuser with the given email and password.
    """
    extra_fields.setdefault("is_staff", True)
    extra_fields.setdefault("is_superuser", True)

    if extra_fields.get("is_staff") is not True:
      raise ValueError("Superuser must have is_staff=True.")
    if extra_fields.get("is_superuser") is not True:
      raise ValueError("Superuser must have is_superuser=True.")

    return self.create_user(email, password, **extra_fields)


class AbstractCustomUser(AbstractBaseUser, PermissionsMixin):
  name_arabic = models.CharField(max_length=255, null=True, blank=True)
  name_english = models.CharField(max_length=255, null=True, blank=True)
  email = models.EmailField(unique=True)
is_active = models.BooleanField(default=True, null=False)
is_staff = models.BooleanField(default=False, null=False)
  profile_picture_url = models.URLField(max_length=1000, null=True, blank=True)

try:
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    objects = CustomUserManager()
except Exception as e:
    print(f"An error occurred: {e}")

  class Meta:
    abstract = True

  def __str__(self):
    return f"{self.name_english}"
