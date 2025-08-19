from rest_framework import serializers

from .models.payment import Plan
from .models.dashboard_user import UserSubscription


class PlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Plan
        fields = "__all__"

class UserSubscriptionSerializer(serializers.ModelSerializer):
    plan = PlanSerializer(read_only=True)

    class Meta:
        model = UserSubscription
        fields = [
            'id',
            'plan',
            'current_credits',
            'subscription_start',
            'subscription_end',
            'feature_credits',
            'is_active',
            'auto_renew',
        ]
