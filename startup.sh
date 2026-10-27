#!/usr/bin/env bash
set -e
# Azure App Service Linux: configure DATA_DIR=/home/data for persistence across deployments.
mkdir -p "${DATA_DIR:-/home/data}" "${UPLOAD_DIR:-${DATA_DIR:-/home/data}/uploads}"
exec gunicorn --bind "0.0.0.0:${PORT:-8000}" --workers 2 --threads 4 --timeout 120 app:app
