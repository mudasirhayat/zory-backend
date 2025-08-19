from django.contrib import admin
from .models.merchant_user import User
from .models.dashboard_user import DashboardUser, UserSubscription
from .models.payment import Plan, UserPaymentProfile

# Register your models here.
admin.site.register(User)
admin.site.register(DashboardUser)
admin.site.register(Plan)
admin.site.register(UserSubscription)
admin.site.register(UserPaymentProfile)
