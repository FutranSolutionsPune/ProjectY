# Futran Solutions Ticket Management System

A role-based internal helpdesk built with Flask + SQLite. Designed for Azure App Service on Linux.

## Included
- First-run setup creates the initial administrator; setup disables itself afterward.
- Admin portal to create/deactivate projects, create accounts, assign roles, disable accounts, and review recent tickets.
- Regular-user portal to submit tickets with priority, descriptions, and image screenshots; view own tickets and threaded updates.
- Engineer queue, atomic ticket pickup, ownership checks, rich-text replies, screenshots, and status lifecycle.
- Open / In Progress / Resolved / Closed buckets with preserved history.
- Password hashing, CSRF tokens, role/ownership authorization, secure session cookie options, screenshot extension/signature checks, size limits, private attachment routes, and conservative rich-text sanitization.

## Run locally
Requires Python 3.11+.

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:8000`. On first run you will be sent to `/setup` to create the first admin. Then sign in and add projects and accounts. There are no hard-coded demo credentials.

## Deploy to Azure App Service (Linux)
1. Create an Azure App Service using a supported Python runtime (Python 3.11 or 3.12) and Linux.
2. In **Configuration / Environment variables**, add:
   - `SECRET_KEY`: a long random secret generated privately (do not use the example value).
   - `DATA_DIR=/home/data`
   - `UPLOAD_DIR=/home/data/uploads`
   - `SQLITE_PATH=/home/data/tickets.db`
   - `COOKIE_SECURE=1`
3. Ensure App Service **persistent storage** is enabled. SQLite and uploaded screenshots live under `/home/data`, outside the deployed application directory, so they survive app package deployments. Back this directory up regularly.
4. Set the startup command to `bash startup.sh` (or `gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120 app:app`).
5. Set `SCM_DO_BUILD_DURING_DEPLOYMENT=true` in App Service environment variables so Azure installs `requirements.txt`. Zip the *contents* of this folder (so `app.py`, `requirements.txt`, `startup.sh`, `templates/`, and `static/` are at ZIP root), then deploy the ZIP using Azure App Service ZIP deployment / Deployment Center. Azure must install `requirements.txt` during build; enable build automation if required by your deployment path.
6. Browse to the app. The first visitor will see one-time admin setup. Create the admin with a strong unique password. Add projects, then create users and engineers from **Admin → People & access**.
7. Under App Service **Networking → Access restrictions**, allow only Futran Solutions' approved office public egress IP addresses and deny other inbound sources. If staff use VPN, allow the VPN egress IPs too. Confirm the rule order and test from both office/VPN and an external network. Do not rely on the URL being obscure.
8. Keep HTTPS enabled. `COOKIE_SECURE=1` requires HTTPS (which Azure App Service normally provides on the default hostname).

## SQLite / production notes
SQLite is appropriate for a small internal prototype or low-concurrency team. App Service should run a single app instance for SQLite; multiple instances do not share local disks consistently and SQLite is not a distributed database. If the ticket volume or concurrent users grow, migrate to Azure SQL and Blob Storage. Back up `/home/data/tickets.db` and `/home/data/uploads/` together. The app currently has no email notifications, password-reset flow, or self-service signup; admins create accounts directly.

## Security boundaries
- The app does not implement office IP filtering itself; enforce this in Azure App Service access restrictions / network controls.
- Use a unique secret key in Azure settings, never in source control.
- Admins must share temporary passwords through a secure channel. A password-change/reset flow is a sensible next production enhancement.
- Review the app against your organization's security requirements before production use.
