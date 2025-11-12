import os
import os
from celery import Celery

try:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mesaky_backend.settings")
    app = Celery("mesaky_backend")
except Exception as e:
    print(f"An

# Load task modules from all registered Django app configs.
app.config_from_object("django.conf:settings", namespace="CELERY")

# Autodiscover tasks from installed Django apps
app.autodiscover_tasks()
