ARG PYTHON_VERSION=3.13
FROM python:${PYTHON_VERSION}-slim

WORKDIR /app
ADD ./proxy.py ./
RUN pip install --no-cache-dir gunicorn

CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:8000", "proxy:application"]
