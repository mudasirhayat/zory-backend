from django.contrib import admin
from .models.merchant_user import User
from .models.dashboard_user import DashboardUser, UserSubscription
from .models.payment import Plan, UserPaymentProfile

# Register your models here.
models = [User, DashboardUser, Plan]
admin.site.register(models)
admin.site.register(UserSubscription)
admin.site.register(UserPaymentProfile)
