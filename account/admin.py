from django.contrib import admin
from .models.merchant_user import User
from .models.dashboard_user import DashboardUser, UserSubscription

try:
    # Your existing code here
except Exception as e:
    print(f"An error occurred: {
from .models.payment import Plan, UserPaymentProfile
from django.contrib import admin

try:
    admin.site.register([User, DashboardUser, Plan])
except Exception as e:
try:
    admin.site.register(UserSubscription)
    admin.site.register(UserPaymentProfile)
except Exception as e:
    print(f"An error occurred: {e}")
