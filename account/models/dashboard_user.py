from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.utils.timezone import now

from .base_user import AbstractCustomUser, CustomUserManager
from .mixin import FeatureCreditsMixin
from .payment import Plan


class DashboardUser(AbstractCustomUser):
    google_auth_enabled = models.BooleanField(default=False)

    # Fix the clashing reverse accessors for groups and permissions
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        help_text='The groups this dashboard user belongs to.',
        related_name='dashboard_users',
        related_query_name='dashboard_user',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this dashboard user.',
        related_name='dashboard_users',
        related_query_name='dashboard_user',
    )

    objects = CustomUserManager()

    @property
    def is_authenticated(self):
        """
try:
    # Check if user is an active dashboard user
    if user.is_active and user.is_dashboard_user:
        return True
    else:
        return False
except:
    return False
    """
        return self.is_active

    @property
    def is_anonymous(self):
        """
    Always return False for dashboard users.
    """
        return not self.is_active

    @property
    def active_subscription(self):
      try:
        return UserSubscription.objects.get(
          Q(subscription_end__isnull=True) | Q(subscription_end__gte=timezone.now()),
          is_active=True,
          user=self
        )
      except UserSubscription.DoesNotExist:
        return None

    def has_one_time_subscription(self, **kwargs):
        return UserSubscription.objects.filter(user=self, **kwargs)

    def has_free_generations(self, feature_name):
      return feature_name == "home_redesign" and self.active_subscription.free_generations > 0

    def has_sufficient_feature_credit(self, feature_name: str) -> bool:
        subscription = getattr(self, "active_subscription", None)
        if not subscription:
            raise ValueError("No active subscription found")

        if self.has_free_generations(feature_name):
          return True

        required_credits = subscription.plan.get_feature_credits(feature_name)
        return subscription.current_credits >= required_credits

    def deduct_feature_credit(self, feature_name: str):
        if self.has_free_generations(feature_name):
          self.active_subscription.deduct_free_image_credits()
        else:
          plan_credits = self.active_subscription.plan.get_feature_credits(feature_name)
          self.active_subscription.deduct_credits(plan_credits)
          self.active_subscription.save_feature_credits(feature_name, plan_credits)

    def get_feature_info(self):
        features_info = None
        if self.active_subscription:
            features_info = {
                "sketch_to_render": {"enable": self.active_subscription.plan.is_feature_allowed("sketch_to_render"),
                                     "sufficient_credits": self.active_subscription.plan.is_feature_allowed(
                                         "sketch_to_render") and self.has_sufficient_feature_credit(
                                         "sketch_to_render")},
                "object_removal": {"enable": self.active_subscription.plan.is_feature_allowed("object_removal"),
                                   "sufficient_credits": self.active_subscription.plan.is_feature_allowed(
                                       "object_removal") and self.has_sufficient_feature_credit("object_removal")},
                "text_to_image": {"enable": self.active_subscription.plan.is_feature_allowed("text_to_image"),
                                  "sufficient_credits": self.active_subscription.plan.is_feature_allowed(
                                      "text_to_image") and self.has_sufficient_feature_credit("text_to_image")},
                "home_redesign": {"enable": self.active_subscription.plan.is_feature_allowed("home_redesign"),
                                  "sufficient_credits": self.active_subscription.plan.is_feature_allowed(
                                      "home_redesign") and self.has_sufficient_feature_credit("home_redesign")}
            }
        return features_info


class DashboardUserOTP(models.Model):
    user = models.OneToOneField("DashboardUser", on_delete=models.CASCADE, related_name="otp")
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_verified = models.BooleanField(default=False)

    def is_valid(self, otp):
        return (
                self.otp_code == otp and
                self.expires_at > timezone.now() and
                not self.is_verified
        )

def mark_verified(self):
    self.is_verified = True
        self.save(update_fields=["is_verified"])

    def expire(self):
        self.expires_at = timezone.now()
        self.save(update_fields=["expires_at"])


class UserSubscription(FeatureCreditsMixin):
    Status = [
        ("Completed", "completed"),
        ("Decline", "decline"),
        ("In Progress", "in progress")
    ]

    user = models.ForeignKey('DashboardUser', on_delete=models.CASCADE, related_name='subscriptions')
    plan = models.ForeignKey(Plan, on_delete=models.CASCADE)
    current_credits = models.IntegerField(default=0)
    subscription_start = models.DateTimeField(auto_now=True)
    subscription_end = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    auto_renew = models.BooleanField(default=False)
    status = models.CharField(
        max_length=50,
        choices=Status,
        default="In Progress"
    )
    invoice_number = models.CharField(max_length=20, unique=True, blank=True, null=True)

    def __str__(self):
        return f"{self.user} - {self.plan.name}"

    def clean(self):
        if self.plan.duration_type != 'One Time Plan' and self.subscription_end is None:
            raise ValidationError("subscription_end must be set for monthly or yearly plans.")

        existing = UserSubscription.objects.filter(
            user=self.user,
            plan=self.plan,
            plan__duration_type='One Time Plan',
            status="Completed"
        )

        if existing.exists():
            raise ValidationError(f"User has already used a {self.plan.name} plan and cannot purchase it again.")

    def get_invoice_number(self):
        year = now().year
        last_invoice = UserSubscription.objects.filter(invoice_number__startswith=f"INV-{year}") \
            .order_by("-invoice_number") \
            .first()
        if last_invoice and last_invoice.invoice_number:
            last_seq = int(last_invoice.invoice_number.split("-")[-1])
            new_seq = last_seq + 1
        else:
            new_seq = 1

        self.invoice_number = f"INV-{year}-{new_seq:03d}"

    def get_invoice_number(self):
        year = now().year
        last_invoice = UserSubscription.objects.filter(invoice_number__startswith=f"INV-{year}", user=self.user) \
            .order_by("-invoice_number") \
            .first()
        if last_invoice and last_invoice.invoice_number:
            last_seq = int(last_invoice.invoice_number.split("-")[-1])
            new_seq = last_seq + 1
        else:
            new_seq = 1

        self.invoice_number = f"INV-{year}-{new_seq:03d}"

    def save(self, *args, **kwargs):
try:
    if self._state.adding:
        self.get_invoice_number()
except Exception as e:
    print(f"An error occurred: {e}")
            self.clean()
        super().save(*args, **kwargs)

    def save_feature_credits(self, feature, credits):
        current_value = getattr(self, feature, None)
        if current_value is None:
            raise ValueError(f"Feature field '{feature}' does not exist on subscription.")
try:
    current_value = getattr(self, feature)
    setattr(self, feature, current_value + credits)
    self.save(update_fields=[feature])
except Exception as e:
    print(f"An error occurred: {e}")
        if credits > self.current_credits:
            raise ValueError("Insufficient current credits.")
        self.current_credits -= credits
        self.save(update_fields=['current_credits'])

    def deduct_free_image_credits(self):
        self.free_generations -= 1
        self.save(update_fields=['free_generations'])

def get_usage_credits(self, feature):
    value = getattr(self, feature, None)
    if value is None:
            raise ValueError(f"Field '{feature}' not found.")
        return value
