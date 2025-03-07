import base64
import json
import logging
import os
import time
from wsgiref.simple_server import make_server

import requests

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

KEYCLOAK_BASE_URL = os.environ.get("KEYCLOAK_BASE_URL")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM")
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID")
KEYCLOAK_CLIENT_SECRET = os.environ.get("KEYCLOAK_CLIENT_SECRET")
PROXY_UPSTREAM_URL = os.environ.get("PROXY_UPSTREAM_URL")
PROXY_AUTH_COOKIE_NAME = os.environ.get("PROXY_AUTH_COOKIE_NAME")
PROXY_AUTHORIZATION = os.environ.get("PROXY_AUTHORIZATION", None)
PROXY_TOKEN_USERNAME = os.environ.get("PROXY_TOKEN_USERNAME", "__token__")

KEYCLOAK_TOKEN_URL = f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
KEYCLOAK_INTROSPECT_URL = f"{KEYCLOAK_TOKEN_URL}/introspect"


def _get_credentials(environ):
    """Extract username and password/token from Authorization header."""
    auth_header = environ.get("HTTP_AUTHORIZATION", "")
    if not auth_header.startswith("Basic "):
        return None, None
    try:
        decoded = base64.b64decode(auth_header.split(" ")[1]).decode()
        username, password = decoded.split(":", 1)
        return username, password
    except (IndexError, ValueError, UnicodeDecodeError):
        return None, None


def _issue_token(username, password):
    """Get access token from Keycloak token endpoint."""
    data = {
        "grant_type": "password",
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_CLIENT_SECRET,
        "username": username,
        "password": password,
    }
    try:
        resp = requests.post(
            KEYCLOAK_TOKEN_URL, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=10
        )
        resp.raise_for_status()
        response_data = resp.json()
        return response_data.get("access_token")
    except requests.RequestException as e:
        logger.error(f"Keycloak request failed: {e}")
        return None


def _introspect_token(token):
    """Introspect a Keycloak token and return True if active."""
    data = {
        "token": token,
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_CLIENT_SECRET,
    }
    try:
        resp = requests.post(
            KEYCLOAK_INTROSPECT_URL,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        resp.raise_for_status()
        response_data = resp.json()
        return response_data.get("active", False)
    except requests.RequestException as e:
        logger.error(f"Token introspection failed: {e}")
        return False


def _get_token_expiry(token):
    """Extract expiration time from Keycloak JWT token."""
    try:
        payload = json.loads(base64.b64decode(token.split(".")[1] + "==").decode("utf-8"))
        exp = payload.get("exp", 0)
        expires_in = max(exp - int(time.time()), 0)
        return expires_in
    except (IndexError, ValueError, json.JSONDecodeError):
        return 3600


def _get_cookie_token(environ):
    """Extract Keycloak JWT token from cookie."""
    cookie = environ.get("HTTP_COOKIE", "")
    if PROXY_AUTH_COOKIE_NAME not in cookie:
        return None
    try:
        return cookie.split(PROXY_AUTH_COOKIE_NAME + "=")[1].split(";")[0]
    except IndexError:
        return None


def application(environ, start_response):
    """WSGI application to handle requests."""
    method = environ["REQUEST_METHOD"]
    path = environ["PATH_INFO"]

    # Check cookie
    token = _get_cookie_token(environ)
    if token is not None and _get_token_expiry(token) > 0:
        return proxy_to_upstream(method, path, environ, start_response, token)

    # Check credentials
    username, password = _get_credentials(environ)
    if username is None:
        return send_unauthorized(start_response, "Missing or invalid Authorization header")

    # Token introspection if username is PROXY_TOKEN_USERNAME
    if username == PROXY_TOKEN_USERNAME:
        if _introspect_token(password):
            return proxy_to_upstream(method, path, environ, start_response, password)
        else:
            return send_unauthorized(start_response, "Invalid or inactive token")
    # Validate credentials via Keycloak for other usernames
    else:
        token = _issue_token(username, password)
        if token:
            return proxy_to_upstream(method, path, environ, start_response, token)
        else:
            return send_unauthorized(start_response, "Invalid credentials")


def proxy_to_upstream(method, path, environ, start_response, token):
    """Forward request to upstream and return response, including 40x/50x from upstream."""
    query_string = environ.get("QUERY_STRING", "")
    upstream_url = f"{PROXY_UPSTREAM_URL}{path}" + (f"?{query_string}" if query_string else "")
    content_length = int(environ.get("CONTENT_LENGTH", 0))
    payload = (
        environ["wsgi.input"].read(content_length)
        if content_length > 0 and method in ["POST", "PUT", "PATCH"]
        else None
    )

    # Assemble headers to be forwarded
    headers = {}
    for key, value in environ.items():
        # Exclude Authorization header
        if key == "HTTP_AUTHORIZATION":
            continue
        # Collect HTTP_* headers
        if key.startswith("HTTP_"):
            header_name = key[5:].replace("_", "-").title()
            headers[header_name] = value
        # Collect non-HTTP_* standard headers
        elif key in ["CONTENT_TYPE", "CONTENT_LENGTH"]:
            header_name = key.replace("_", "-").title()
            headers[header_name] = value
    # Add reverse proxy headers
    headers["X-Forwarded-For"] = environ.get("HTTP_X_FORWARDED_FOR", environ.get("REMOTE_ADDR", "unknown"))
    headers["X-Forwarded-Host"] = environ.get("HTTP_X_FORWARDED_HOST", environ.get("HTTP_HOST", "localhost:8000"))
    headers["X-Forwarded-Proto"] = environ.get("HTTP_X_FORWARDED_PROTO", environ.get("wsgi.url_scheme", "http"))

    proxy_authorization = PROXY_AUTHORIZATION.lower()
    if proxy_authorization == "basic":
        # Forward basic auth as-is
        headers["Authorization"] = environ["HTTP_AUTHORIZATION"]
    elif proxy_authorization == "bearer":
        # Use the toekn as Bearer token
        headers["Authorization"] = f"Bearer {token}"
    else:
        # Do not forward authorization
        pass

    try:
        resp = requests.request(
            method=method,
            url=upstream_url,
            headers=headers,
            data=payload,
            timeout=10,
            allow_redirects=False,
        )
        response_headers = [(k, v) for k, v in resp.headers.items()]
        status = f"{resp.status_code} {resp.reason}"
        body = resp.content
        if token:
            expires_in = _get_token_expiry(token)
            response_headers.append(
                ("Set-Cookie", f"{PROXY_AUTH_COOKIE_NAME}={token}; Max-Age={expires_in}; Path=/; HttpOnly")
            )
        start_response(status, response_headers)
        return [body]
    except requests.RequestException as e:
        # network-level failure
        logger.error(f"Upstream request failed: {e}")
        start_response("502 Bad Gateway", [("Content-Type", "text/plain")])
        return [b"Bad Gateway"]


def send_unauthorized(start_response, message):
    """Send a 401 response with a message."""
    headers = [("WWW-Authenticate", 'Basic realm="Proxy"')]
    start_response("401 Unauthorized", headers)
    return [message.encode()]


if __name__ == "__main__":
    # For testing with wsgiref (single-threaded)
    logger.info("Starting proxy server (wsgiref)")
    httpd = make_server("0.0.0.0", 8000, application)
    logger.info("Proxy server started on :8000")
    httpd.serve_forever()
