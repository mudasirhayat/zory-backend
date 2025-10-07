from rest_framework.permissions import BasePermission
from account.models import DashboardUser, User
from rest_framework.permissions import BasePermission

class IsAuthenticatedDashboardUser(BasePermission):
    """
    Allows access only to authenticated dashboard users.
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
