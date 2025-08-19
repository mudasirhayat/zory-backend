#!/bin/bash

# Exit script on any error
set -e

echo "Running database migrations..."
python manage.py migrate --noinput

# Collect static files (optional, if you're serving static files via Django)
echo "Collecting static files..."
python manage.py collectstatic --noinput

# Create a superuser if it doesn't already exist
echo "Creating superuser..."
python manage.py shell <<EOF
import os
from django.contrib.auth import get_user_model

User = get_user_model()

email = os.getenv('DJANGO_SUPERUSER_EMAIL', 'admin@example.com')
password = os.getenv('DJANGO_SUPERUSER_PASSWORD', 'password')

if not User.objects.filter(email=email).exists():
    User.objects.create_superuser(email=email, password=password)
    print(f"Superuser '{email}' created.")
else:
    print(f"Superuser '{email}' already exists.")
EOF

# Start the application
echo "Starting application..."
exec "$@"
