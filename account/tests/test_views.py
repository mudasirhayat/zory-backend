# account/tests/test_views.py

from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class AccountViewTests(APITestCase):

    def setUp(self):
        # Create a regular user and a superuser
        self.user = User.objects.create_user(
            email="testuser@example.com", password="testpass123"
        )
        self.admin = User.objects.create_superuser(
            email="admin@example.com", password="adminpass123"
        )
        # URLs based on provided URL patterns (corrected with reverse names)
        self.register_url = reverse("account:register")
        self.login_url = reverse("account:token_obtain_pair")
        self.token_refresh_url = reverse("account:token_refresh")
        self.token_verify_url = reverse("account:token_verify")
        self.user_list_url = reverse("account:user-list")
        self.profile_url = reverse("account:profile")
        self.change_password_url = reverse("account:change-password")
        self.delete_profile_url = reverse(
            "account:delete-user", kwargs={"pk": self.user.id}
        )
        self.password_reset_url = reverse("account:password-reset-complete")

    def get_access_token(self, email="testuser@example.com", password="testpass123"):
        """
        Helper method to get JWT access token for authentication.
        """
        response = self.client.post(
            self.login_url, {"email": email, "password": password}, format="json"
        )

        if response.status_code != 200:
            raise ValueError(f"Failed to get access token. Response: {response.data}")

        return response.data["access"]

    def authenticate(self, user=None):
        """Helper method to authenticate a user and set the authorization header."""
        user = user or self.user
        refresh = RefreshToken.for_user(user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

    # User Registration Tests
    def test_user_registration_success(self):
        data = {
            "email": "newuser@example.com",
            "password": "strongpass123",
            "confirm_password": "strongpass123",
        }

        response = self.client.post(self.register_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_user_registration_existing_email(self):
        """Test registration fails if email already exists."""
        data = {"email": "testuser@example.com", "password": "testpass123"}
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_user_registration_no_password(self):
        """Test registration fails when password is missing."""
        data = {"email": "user@example.com"}
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # Authentication Tests
    def test_login_with_valid_credentials(self):
        """Test successful login."""
        data = {"email": "testuser@example.com", "password": "testpass123"}
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)

    def test_login_with_invalid_credentials(self):
        """Test login fails with wrong credentials."""
        data = {"email": "testuser@example.com", "password": "wrongpass"}
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_token_refresh_valid(self):
        """Test token refresh with a valid token."""
        self.authenticate()
        refresh = RefreshToken.for_user(self.user)
        response = self.client.post(self.token_refresh_url, {"refresh": str(refresh)})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_token_verification(self):
        """Test token verification."""
        self.authenticate()
        refresh = RefreshToken.for_user(self.user)
        response = self.client.post(
            self.token_verify_url, {"token": str(refresh.access_token)}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    # Profile Management Tests
    def test_get_user_profile_authenticated(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_get_user_profile_unauthenticated(self):
        """Test profile retrieval fails when unauthenticated."""
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_profile_update_valid(self):
        """Test successful profile update."""
        self.authenticate()
        data = {"name": "Test User", "phone": "+1234567890"}
        response = self.client.patch(self.profile_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_profile_update_invalid_data(self):
        # Authenticate the user
        self.client.login(email="testuser@example.com", password="testpass123")

        # Invalid data for update
        data = {"name": None, "phone": "invalid-phone"}

        response = self.client.patch(
            self.profile_url,
            data,
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {self.get_access_token()}",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # Password Management Tests
    def test_password_change_valid(self):
        # Authenticate the user
        self.client.login(email="testuser@example.com", password="testpass123")

        # Prepare data for password change
        data = {
            "old_password": "testpass123",
            "password": "newtestpass456",
            "confirm_password": "newtestpass456",
        }

        # Include authentication token in the request
        response = self.client.patch(
            self.change_password_url,
            data,
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {self.get_access_token()}",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_password_change_invalid_old_password(self):
        """Test password change fails with incorrect old password."""
        self.authenticate()
        data = {"old_password": "wrongpass", "new_password": "newpass123"}
        response = self.client.patch(self.change_password_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

def test_password_reset_invalid_data(self):
    """Test password reset fails with invalid data."""
    data = {"email": "", "new_password": ""}
    
    if not data["email"] or not data["new_password"]:
        raise ValueError("Invalid
        response = self.client.patch(self.password_reset_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # Profile Deletion Tests
    def test_profile_deletion_authenticated(self):
        """Test profile deletion by authenticated user."""
        self.authenticate()
        response = self.client.delete(self.delete_profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_profile_deletion_unauthenticated(self):
        """Test profile deletion fails without authentication."""
        response = self.client.delete(self.delete_profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # Admin Access Tests
def test_user_list_view_as_admin(self):
    try:
        """Test admin can view user list."""
    except Exception as e:
        self.fail(f"An error occurred: {str(e)}")
        self.authenticate(user=self.admin)
response = self.client.get(self.user_list_url)
self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_user_list_view_as_user_denied(self):
        # Authenticate as a regular user
        self.client.login(email="testuser@example.com", password="testpass123")

        response = self.client.get(
            self.user_list_url, HTTP_AUTHORIZATION=f"Bearer {self.get_access_token()}"
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
