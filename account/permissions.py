from rest_framework.permissions import BasePermission
from account.models import DashboardUser, User
from rest_framework.permissions import BasePermission
from rest_framework.exceptions import PermissionDenied

class IsAuthenticatedDashboardUser(BasePermission):
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated and request.user.is_dashboard_user:
    """

    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        return isinstance(user, DashboardUser) and bool(user and user.is_authenticated)


class IsAuthenticated(BasePermission):
    """
    Allows access only to authenticated users.
    """

    def has_permission(self, request, view):
      user = getattr(request, "user", None)
      return isinstance(user, User) and bool(user and user.is_authenticated)
