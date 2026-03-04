#!/bin/sh
exec poetry run gunicorn -c gunicorn_conf.py "app:create_app()"
