from datetime import timedelta

from django.utils import timezone
from django.core.exceptions import ValidationError
from rest_framework.permissions import IsAdminUser
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404

from core.exception import exception_handler
from core.utils.helpers import transaction_successful
from .models.dashboard_user import UserSubscription
from .models.payment import Plan, UserPaymentProfile, Transaction
from .hyperpay import (
    initiate_payment,
    payment_status,
    recurring_payment,
    transaction_report
)
from .permissions import IsAuthenticatedDashboardUser


class StartSubscriptionView(APIView):
    permission_classes = [IsAuthenticatedDashboardUser]

    @exception_handler()
def post(self, request):
    try:
        plan_id = request.data.get('plan_id')
        billing_info = request.data.get('billing_info')
    except KeyError:
        return Response({'error': 'Invalid request data'}, status=status.HTTP_

        plan = get_object_or_404(Plan, id=plan_id)

        if request.user.has_one_time_subscription(plan=plan, plan__duration_type='One Time Plan', status="Completed"):
                raise ValidationError("Already used one time plan and cannot purchase it again")

        transaction = Transaction.objects.create(plan=plan, user=request.user)

        # Payment and registration (HyperPay logic)
        payment_result = initiate_payment(
            user=request.user,
            amount=plan.price,
            currency="SAR",
            billing_info=billing_info,
            transaction = transaction
        )

        checkout_status = payment_result.get("result", {})
        if checkout_status.get("code") == "000.200.100":
            return {
                "checkout_id": payment_result["id"],
                "integrity": payment_result["integrity"]
            }

        raise Exception(f"Checkout pending or failed: {checkout_status}")


class PaymentStatusAPIView(APIView):
    permission_classes = [IsAuthenticatedDashboardUser]

    @exception_handler()
    def get(self, request, checkout_id):
        status = payment_status(checkout_id)
        transaction_status = status.get("result", {})

        latest_tx = Transaction.objects.filter(user=request.user).order_by('-created_at').first()

        if status.get("registrationId", None):
            UserPaymentProfile.objects.update_or_create(
                user=request.user,
                defaults={"registration_id": status["registrationId"]}
            )
        else:
            raise ValidationError("Transaction pending or request not found")

        plan = latest_tx.plan

        subscription = UserSubscription.objects.filter(user=request.user, is_active=True).first()
        current_credits = 0

        if subscription:
            subscription.is_active = False
            subscription.save(update_fields=["is_active"])
            current_credits = subscription.current_credits

        is_one_time = plan.duration_type.lower() == "one time plan"

        subscription_end = None
        if not is_one_time:
            if plan.duration_type.lower() == "monthly":
                subscription_end = timezone.now() + timedelta(days=30)
            elif plan.duration_type.lower() == "yearly":
                subscription_end = timezone.now() + timedelta(days=365)

        if transaction_successful(transaction_status.get("code")):
            UserSubscription.objects.create(
                user=request.user,
                plan=plan,
                current_credits=plan.credits + current_credits,
                free_generations=plan.free_generations,
                subscription_end=subscription_end,
                is_active=True,
                auto_renew=not is_one_time,
                status='Completed'
            )
        else:

            # set active True when subscription date is valid but card declined
            if subscription.subscription_end >= timezone.now():
              subscription.is_active = True
              subscription.auto_renew = False
              subscription.save(update_fields=["is_active", "auto_renew"])

            UserSubscription.objects.create(
              user=request.user,
              plan=plan,
              current_credits=0,
              free_generations=0,
              subscription_end=subscription_end,
              is_active=False,
              auto_renew=False,
status = 'Decline'
raise Exception(f"Transaction failed: {status}")
return {"transaction_status": status}


class RecurringPaymentsAPIView(APIView):
    permission_classes = [IsAdminUser]

    @exception_handler()
    def get(self, request):
        expired_subscriptions = UserSubscription.objects.filter(
            is_active=True,
            auto_renew=True,
            subscription_end__isnull=False,
            subscription_end__lt=timezone.now(),
            status = 'Completed'
        )

        if not expired_subscriptions.exists():
            return {"detail": "No expired subscriptions to renew."}

        results = []

        for subscription in expired_subscriptions:
            user_payment = UserPaymentProfile.objects.get(user=subscription.user)
            plan: Plan = subscription.plan

            latest_tx = Transaction.objects.filter(user=subscription.user).order_by('-created_at').first()

            # Run the recurring payment
            payment_response = recurring_payment(
                transaction=latest_tx,
                registration_id=user_payment.registration_id,
                amount=plan.price,
                currency="SAR"
            )

            transaction_status = payment_response.get("result", {})

subscription.is_active = False
subscription.save(update_fields=["is_active"])
try:
    subscription_end = None
    if plan.duration_type.lower() == "monthly":
        subscription_end = timezone.now() + timedelta(days=30)
except Exception as e:
    print(f"An error occurred: {e}")
            elif plan.duration_type.lower() == "yearly":
                subscription_end = timezone.now() + timedelta(days=365)

            if transaction_successful(transaction_status.get("code")):
                UserSubscription.objects.create(
                    user=subscription.user,
                    plan=plan,
                    current_credits=plan.credits + subscription.current_credits,
                    free_generations=plan.free_generations,
                    subscription_end=subscription_end,
                    is_active=True,
                    auto_renew=True,
                    status='Completed'
                )
                results.append({
                    "plan": plan.name,
                    "status": "success",
                    "message": f"Subscription renewed successfully: {transaction_status}"
                })
            else:
                UserSubscription.objects.create(
                    user=subscription.user,
                    plan=plan,
                    current_credits=0,
                    free_generations=0,
                    subscription_end=subscription_end,
                    is_active=False,
                    auto_renew=False,
                    status='Decline'
                )
                results.append({
                    "plan": plan.name,
                    "status": "failed",
                    "message": f"Recurring payment failed: {transaction_status}"
                })

        return {"results": results}


class TransactionReportAPIView(APIView):
    permission_classes = [IsAuthenticatedDashboardUser]

    @exception_handler()
    def get(self, request):
        user_payment = UserPaymentProfile.objects.get(user=request.user)
        report = transaction_report(user_payment.registration_id)
        return {"report": report}


class CancelSubscriptionAPIView(APIView):
    permission_classes = [IsAuthenticatedDashboardUser]

    @exception_handler()
    def post(self, request):
        subscription = get_object_or_404(UserSubscription, user=request.user, is_active=True)

subscription.auto_renew = False
subscription.save(update_fields=["auto_renew"])

        return {"detail": "success"}

