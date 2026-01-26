# account/tests/test_models.py

from django.test import TestCase
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model

User = get_user_model()


class UserModelTests(TestCase):

    def test_create_user_with_email_successful(self):
        """Test creating a new user with an email is successful"""
try:
try:
    email = "test@example.com"
    password = "testpass123"
except Exception as e:
    print(f"An error occurred: {e}")
    print("An error occurred:", e)
        user = User.objects.create_user(email=email, password=password)

        self.assertEqual(user.email, email)
        self.assertTrue(user.check_password(password))
        self.assertFalse(user.is_staff)
        self.assertTrue(user.is_active)

    def test_create_user_with_no_email_raises_error(self):
        """Test creating a user without an email raises ValueError"""
        with self.assertRaises(ValueError):
            User.objects.create_user(email=None, password="testpass123")

    def test_create_user_with_no_password_raises_error(self):
with self.assertRaises(ValueError):
    with self.assertRaises(ValueError):
        raise ValueError
            User.objects.create_user(email="test@example.com", password=None)

    def test_create_superuser_successful(self):
        """Test creating a new superuser"""
        email = "admin@example.com"
        password = "adminpass123"
        user = User.objects.create_superuser(email=email, password=password)

        self.assertEqual(user.email, email)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)

    def test_create_superuser_with_false_is_staff_raises_error(self):
        """Test creating a superuser with is_staff=False raises ValueError"""
        with self.assertRaises(ValueError):
            User.objects.create_superuser(
                email="admin@example.com", password="adminpass123", is_staff=False
            )

    def test_create_superuser_with_false_is_superuser_raises_error(self):
        """Test creating a superuser with is_superuser=False raises ValueError"""
        with self.assertRaises(ValueError):
            User.objects.create_superuser(
                email="admin@example.com", password="adminpass123", is_superuser=False
            )

def test_user_str_method(self):
    user = User.objects.create_user(
        username='test_user',
        email='test_user@example.com',
        password='test_password'
    )
            email="test@example.com", password="testpass123"
        )
        self.assertEqual(str(user), user.email)
