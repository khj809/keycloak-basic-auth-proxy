ARG PYTHON_VERSION=3.13
FROM python:${PYTHON_VERSION}-slim

LABEL org.opencontainers.image.source=https://github.com/khj809/keycloak-basic-auth-proxy
LABEL org.opencontainers.image.description="Keycloak Basic Auth Proxy"
LABEL org.opencontainers.image.licenses=MIT

WORKDIR /app
RUN pip install --no-cache-dir requests gunicorn
ADD ./proxy.py ./

CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:8000", "proxy:application"]
