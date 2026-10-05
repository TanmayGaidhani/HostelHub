import os

# Gunicorn configuration file for production deployment
# Binds automatically to 0.0.0.0:$PORT required by Render and cloud hosts
port = os.environ.get("PORT", "10000")
bind = f"0.0.0.0:{port}"

workers = 2
threads = 4
timeout = 120
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = "info"
