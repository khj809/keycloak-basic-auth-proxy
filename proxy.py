import base64
import json
import logging
import os
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from wsgiref.simple_server import make_server

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

KEYCLOAK_BASE_URL = os.environ.get("KEYCLOAK_BASE_URL")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM")
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID")
KEYCLOAK_CLIENT_SECRET = os.environ.get("KEYCLOAK_CLIENT_SECRET")
PROXY_UPSTREAM_URL = os.environ.get("PROXY_UPSTREAM_URL")
PROXY_AUTH_COOKIE_NAME = os.environ.get("PROXY_AUTH_COOKIE_NAME")
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
        req = Request(
            KEYCLOAK_TOKEN_URL,
            data=urlencode(data).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urlopen(req, timeout=10) as resp:
            response_data = json.loads(resp.read().decode())
            return response_data.get("access_token")
    except (HTTPError, URLError) as e:
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
        req = Request(
            KEYCLOAK_INTROSPECT_URL,
            data=urlencode(data).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urlopen(req, timeout=10) as resp:
            response_data = json.loads(resp.read().decode())
            return response_data.get("active", False)
    except (HTTPError, URLError) as e:
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


def _validate_cookie(environ):
    """Validate Keycloak JWT token from cookie by checking expiration."""
    cookie = environ.get("HTTP_COOKIE", "")
    if PROXY_AUTH_COOKIE_NAME not in cookie:
        return False
    try:
        token = cookie.split(PROXY_AUTH_COOKIE_NAME + "=")[1].split(";")[0]
        return _get_token_expiry(token) > 0
    except IndexError:
        return False


def application(environ, start_response):
    """WSGI application to handle requests."""
    method = environ["REQUEST_METHOD"]
    path = environ["PATH_INFO"]

    # Check cookie
    if _validate_cookie(environ):
        return proxy_to_upstream(method, path, environ, start_response)

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


def proxy_to_upstream(method, path, environ, start_response, token=None):
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
        # Collect HTTP_* headers
        if key.startswith("HTTP_"):
            header_name = key[5:].replace("_", "-").title()
            headers[header_name] = value
        # Collect non-HTTP_* standard headers
        elif key in ["CONTENT_TYPE", "CONTENT_LENGTH"]:
            header_name = key.replace("_", "-").title()
            headers[header_name] = value
    # Add reverse proxy headers
    headers["X-Forwarded-For"] = environ.get("REMOTE_ADDR", "unknown")
    headers["X-Forwarded-Host"] = environ.get("HTTP_HOST", "localhost:8000")
    headers["X-Forwarded-Proto"] = environ.get("wsgi.url_scheme", "http")

    try:
        req = Request(upstream_url, data=payload, headers=headers, method=method)
        with urlopen(req, timeout=10) as resp:
            response_headers = [(k, v) for k, v in resp.getheaders()]
            if token:
                expires_in = _get_token_expiry(token)
                response_headers.append(
                    ("Set-Cookie", f"{PROXY_AUTH_COOKIE_NAME}={token}; Max-Age={expires_in}; Path=/; HttpOnly")
                )
            status = f"{resp.getcode()} {resp.reason}"
            start_response(status, response_headers)
            return [resp.read()]
    except HTTPError as e:
        # Forward upstream HTTP errors (e.g., 40x, 50x) as-is
        response_headers = [(k, v) for k, v in e.headers.items()]
        status = f"{e.code} {e.reason}"
        start_response(status, response_headers)
        return [e.read()]
    except URLError as e:
        # Return 502 only for errors originating in this script (e.g., network failure)
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
