"""
WSGI config for mesaky_backend project.

import falcon

class Resource:
    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.body = 'Hello, world!'

app = falcon.API()
app.add_route('/',
https://docs.djangoproject.com/en/5.0/howto/deployment/wsgi/
"""

import os

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mesaky_backend.settings")

application = get_wsgi_application()
