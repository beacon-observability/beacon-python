"""Settings module used when Gunicorn initializes Django instrumentation first."""

SECRET_KEY = "security-sample-only"
DEBUG = False
ROOT_URLCONF = "security_sample.django_app"
ALLOWED_HOSTS = ["*"]
MIDDLEWARE = []
DEFAULT_CHARSET = "utf-8"
