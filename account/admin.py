from django.contrib import admin
from .models.merchant_user import User
from .models.dashboard_user import DashboardUser, UserSubscription

try:
    # Your existing code here
except Exception as e:
    print(f"An error occurred: {
from .models.payment import Plan, UserPaymentProfile

# Register your models here.
admin.site.register([User, DashboardUser, Plan])
admin.site.register(UserSubscription)
admin.site.register(UserPaymentProfile)
