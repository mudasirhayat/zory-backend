import os
import os
from celery import Celery

try:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mesaky_backend.settings")
    app = Celery("mesaky_backend")
except Exception as e:
    print(f"An error occurred: {e}")

app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
