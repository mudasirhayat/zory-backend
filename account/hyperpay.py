import os
import requests
from django.conf import settings

HYPERPAY_URL = settings.HYPERPAY_URL
ENTITY_ID_3DS = settings.ENTITY_ID_3DS
ENTITY_ID = settings.ENTITY_ID
AUTH_TOKEN = settings.AUTH_TOKEN

def initiate_payment(amount, currency, user, billing_info, transaction):
    url = f"{HYPERPAY_URL}/v1/checkouts"

    extra_params = {}
    if os.getenv("ENVIRONMENT") != "PROD":
      extra_params = {
        "customParameters[3DS2_enrolled]": "true",
        "testMode": "EXTERNAL",
      }

    data = {
        "entityId": ENTITY_ID_3DS,
        'amount': amount,
        'currency': currency,
        'paymentType': 'DB',
        'integrity': "true",
        "createRegistration": "true",

        # Customer personal details
        "merchantTransactionId": transaction.transaction_id,
        "customer.email": user.email,
        "customer.givenName": billing_info.get("given_name", ""),
        "customer.surname": billing_info.get("surname", ""),

        # User billing address
        "billing.street1": billing_info.get("street1", ""),
        "billing.city": billing_info.get("city", ""),
        "billing.state": billing_info.get("state", ""),
        "billing.country": billing_info.get("country", ""),
        "billing.postcode": billing_info.get("postcode", ""),

        # Card-on-file params
        "standingInstruction.mode": "INITIAL",
        "standingInstruction.type": "UNSCHEDULED",
        "standingInstruction.source": "CIT",
        "standingInstruction.recurringType": "STANDING_ORDER",

        # Recurring custom params and 3DS for test env
        "customParameters[recurringPaymentAgreement]": transaction.agreement_id,
        "customParameters[paymentFrequency]": "OTHER",
        **extra_params
    }

    headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
    r = requests.post(url, data=data, headers=headers)
    return r.json()


def payment_status(checkout_id):
    url = f"{HYPERPAY_URL}/v1/checkouts/{checkout_id}/payment"
    url += f'?entityId={ENTITY_ID_3DS}'

    headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
    r = requests.get(url, headers=headers)
    return r.json()


def recurring_payment(transaction, registration_id, amount, currency):
    url = f"{HYPERPAY_URL}/v1/registrations/{registration_id}/payments"

    extra_params = {}
    if os.getenv("ENVIRONMENT") != "PROD":
      extra_params = { "testMode": "EXTERNAL" }

    data = {
        'entityId': ENTITY_ID,
        'amount': amount,
        'currency': currency,
        'paymentType': 'DB',

        # Card-on-file params
        "standingInstruction.mode": "REPEATED",
        "standingInstruction.source": "MIT",
        "standingInstruction.type": "UNSCHEDULED",

        "customParameters[recurringPaymentAgreement]": transaction.agreement_id,
        **extra_params,
    }

    headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
    r = requests.post(url, data=data, headers=headers)
    return r.json()


def transaction_report(registration_id):
    url = f"{HYPERPAY_URL}/v3/query/{registration_id}"
    url += f'?entityId={ENTITY_ID_3DS}'

    headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
    r = requests.get(url, headers=headers)
    return r.json()
