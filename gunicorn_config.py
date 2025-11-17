"""Gunicorn configuration for WizardView production deployment"""

import multiprocessing
import os

# Server socket - use PORT environment variable for cloud platforms like Render
port = os.getenv('PORT', '5001')
bind = f"0.0.0.0:{port}"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'sync'
worker_connections = 1000
timeout = 30
keepalive = 2

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = 'wizardview'

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# SSL (uncomment and configure for HTTPS)
# keyfile = '/path/to/ssl/key.pem'
# certfile = '/path/to/ssl/cert.pem'

