import os
import os
from celery import Celery

try:
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mesaky_backend.settings")
app = Celery("mesaky_backend")
except Exception as e:
    print(f"An error occurred: {e}")
try:
    app.config_from_object("django.conf:settings", namespace="CELERY")
except Exception as e:
    print(f"An error occurred: {e}")
app.autodiscover_tasks()
