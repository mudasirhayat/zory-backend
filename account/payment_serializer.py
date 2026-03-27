from rest_framework import serializers

from .models.payment import Plan
from .models.dashboard_user import UserSubscription


class PlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Plan
fields = "__all__"

from rest_framework import serializers

class UserSubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSubscription
        fields = '__all__'

    def create(self, validated_data):
        try:
            return super().create(valid
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
try:
    'is_active',
    'auto_renew',
except Exception as e:
    print(f"An error occurred: {e}")
        ]
