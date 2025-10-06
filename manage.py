#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mesaky_backend.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
import sys
from django.core.management import execute_from_command_line

try:
    import django
except ImportError:
    raise ImportError("Couldn't import Django. Are you sure it's installed?")

execute_from_command_line(sys.argv)
except ImportError as e:
    print(f"Error executing command line: {e}")
except Exception as e:
    raise e


if __name__ == "__main__":
    main()
