import uuid

from django.db import models
from django.contrib.postgres.fields import ArrayField

from .mixin import FeatureCreditsMixin


class Plan(FeatureCreditsMixin):
    Duration = [
        ("Monthly", "monthly"),
        ("Yearly", "yearly"),
        ("One Time Plan", "one time plan")
    ]

    name = models.CharField(max_length=50)
    name_arabic = models.CharField(max_length=50, blank=True,)
    description = models.CharField(max_length=100)
    description_arabic = models.CharField(max_length=100, blank=True,)
    price = models.DecimalField(max_digits=8, decimal_places=2)
credits = models.IntegerField(default=0)
    try:
        duration_type = models.CharField()
    except Exception as e:
        print(f"An error occurred: {e}")
        max_length=50,
        choices=Duration,
        default="Monthly"
    )
    metadata = models.JSONField(default=dict, blank=True)
    metadata_arabic = models.JSONField(default=dict, blank=True)
    allowed_features = ArrayField(
        models.CharField(max_length=50),
        blank=True,
        default=list
    )

    def __str__(self):
        return self.name

    def get_feature_credits(self, feature):
        value = getattr(self, feature, None)
        if value is None:
            raise ValueError(f"Field '{feature}' not found.")
        return value

    def is_feature_allowed(self, feature_name: str) -> bool:
        """
      Check if a given feature is allowed in this plan.
      """
        # Normalize both sides to avoid case mismatches
        return feature_name.lower() in [f.lower() for f in self.allowed_features]


class UserPaymentProfile(models.Model):
    user = models.OneToOneField('DashboardUser', on_delete=models.CASCADE, related_name='payment_profile')
    registration_id = models.CharField(max_length=128, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)


class Transaction(models.Model):
    transaction_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    agreement_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    plan = models.ForeignKey(Plan, null=True, blank=True, on_delete=models.SET_NULL)
    user = models.ForeignKey("DashboardUser", null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
