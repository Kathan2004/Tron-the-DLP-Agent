"""WSGI entry point: gunicorn -c gunicorn.conf.py wsgi:app"""

from src.bootstrap import create_app

app = create_app()
