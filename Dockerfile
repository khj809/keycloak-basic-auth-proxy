ARG PYTHON_VERSION=3.13
FROM python:${PYTHON_VERSION}-slim

LABEL org.opencontainers.image.source=https://github.com/khj809/keycloak-basic-auth-proxy
LABEL org.opencontainers.image.description="Keycloak Basic Auth Proxy"
LABEL org.opencontainers.image.licenses=MIT

WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:0.6.6 /uv /bin/uv
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-install-project --group cache
ADD ./proxy.py ./

CMD ["uv", "run", "--no-sync", "gunicorn", "--workers", "4", "--bind", "0.0.0.0:8000", "proxy:application"]
