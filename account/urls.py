from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenVerifyView,
)
from rest_framework.routers import DefaultRouter

from . import views
from .payment_views import StartSubscriptionView, PaymentStatusAPIView, RecurringPaymentsAPIView, \
  TransactionReportAPIView, CancelSubscriptionAPIView

app_name = "account"

router = DefaultRouter()
router.register(r"plans", views.PlanViewSet, basename="plans")

urlpatterns = [
    # For User Registration
    path("register/", views.UserRegistrationView.as_view(), name="register"),
    path("dashboard/register/",views.DashboardUserRegistrationView.as_view(), name="dashboard-user-register"),
path("dashboard/verify/otp/", views.VerifyDashboardUserOtpAndActivateView.as_view(), name="dashboard-user-register-verify"),
path("auth/dashboard/", views.DashboardUserSignInView.as_view(), name="dashboard-user-auth"),
    # For Profile
    path("profile/", views.UserView.as_view(), name="profile"),
    path("profile/dashboard/", views.DashboardUserView.as_view(), name="profile-dashboard"),
    path(
        "profile/password/", views.ChangePasswordView.as_view(), name="change-password"
    ),
    path(
      "dashboard/password/", views.ChangePasswordDashboardView.as_view(), name="change-password-dashboard"
    ),
    path('auth/google/', views.GoogleAuthAPIView.as_view(), name='google_auth'),
    # For Authentication
    path("auth/", views.CustomTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("token/verify/", TokenVerifyView.as_view(), name="token_verify"),
    path("users/list/", views.UserListView.as_view(), name="user-list"),
    path("users/update/<int:pk>", views.UpdateUserRole.as_view(), name="user-update"),
path("users/status/<int:pk>", views.UpdateUserStatus.as_view(), name="user-status-update"),
path("users/delete/<int:pk>", views.DeleteUser.as_view(), name="user-delete"),
    path("dashboard/delete/", views.DashboardUserView.as_view(), name="delete-dashboard-user"),
    # For reset password
    path(
        "reset-password/",
views.ForgotPasswordAPIView.as_view(),
name="forgot-password",
path("password-reset-confirm/",
        views.SetNewPasswordAPIView.as_view(),
        name="password-reset-confirm"),
        name="password-reset-confirm",
    ),
    # For logout
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("dashboard/logout/", views.DashboardLogoutView.as_view(), name="logout-dashboard"),
    path(
        "business-roles/",
        views.BusinessRoleListView.as_view(),
        name="business-roles-list",
    ),
    # subscription urls
    path('subscription/start/', StartSubscriptionView.as_view(), name='start-subscription'),
    path('payment-status/<str:checkout_id>/', PaymentStatusAPIView.as_view(), name='payment-status'),
    path('subscription/recurring/', RecurringPaymentsAPIView.as_view(), name='recurring-payment'),
    path('transaction/report/', TransactionReportAPIView.as_view(), name='transaction-report'),
    path('subscription/cancel/', CancelSubscriptionAPIView.as_view(), name='cancel-subscription'),
    path('dashboard/invoices/', views.InvoiceViewSet.as_view(), name='subscription_invoices')
] + router.urls
