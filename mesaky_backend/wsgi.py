"""
WSGI config for mesaky_backend project.

import falcon

class Resource:
    def on_get(self, req, resp):
try:
    resp.status = falcon.HTTP_200
    resp.body = 'Hello, world!'
except Exception as e:
    resp.status = falcon.HTTP_500
    resp.body = 'Internal Server Error'

class RootResource:
    def on_get(self, req, resp):
resp.status = falcon.HTTP_200
resp.body = json.dumps({'message': 'Hello, World!'})
app.add_route('/', Root)
"""

import os

import os
from django.core.wsgi import get_wsgi_application

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mesaky_backend.settings")
application = get_wsgi_application()
