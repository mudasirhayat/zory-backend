"""
ASGI config for mesaky_backend project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/howto/deployment/asgi/
"""

import os

import sys

try:
    from django.core.asgi import get_asgi_application
    from channels.routing import ProtocolTypeRouter, URLRouter
except ImportError as e:
    print(f"Error importing required modules: {e}")
import logging

logging.basicConfig(level=logging.ERROR)
from channels.sessions import SessionMiddlewareStack
from core.routing import websocket_urlpatterns

application = ProtocolTypeRouter({
    'websocket': SessionMiddlewareStack(
        URLRouter(
            websocket_urlpatterns

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mesaky_backend.settings")

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": SessionMiddlewareStack(
        URLRouter(websocket_urlpatterns)
    ),
})
        "static": get_asgi_application(),
    }
)
