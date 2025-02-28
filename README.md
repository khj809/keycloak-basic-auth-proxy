# Keycloak Basic-Auth Proxy

This repository contains a simple WSGI-based proxy server that handles HTTP Basic Authentication using Keycloak as the identity provider. It leverages Keycloak's access tokens to authenticate requests and forwards authenticated requests to an upstream server. The proxy supports both direct username/password authentication and token-based authentication via introspection.

## Features

The proxy server performs authentication as follows:

1. **Unauthenticated Access**: On unauthenticated requests, it returns a `401 Unauthorized` response with a `WWW-Authenticate` challenge to prompt the user for credentials. These credentials are expected to correspond to users configured in the Keycloak client.
2. **Token Issuance**: Using the provided credentials, the server attempts to issue an access token by calling the Keycloak token endpoint (`/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token`).
3. **Successful Authentication**: If the token is issued successfully, the server forwards the request to the upstream server, sets a cookie (`Set-Cookie` header) containing the access token, and returns the upstream response. Subsequent requests are authenticated using this cookie until the token expires.
4. **Token Introspection**: Optionally, if the username matches a configurable value (`__token__` by default), the server assumes the password is an already-issued Keycloak token. It introspects this token by calling the Keycloak introspection endpoint (`/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token/introspect`). This feature allows clients to use tokens directly without exposing plaintext passwords.
5. **Token Validation**: For requests with a valid cookie, the server checks the token's expiration (extracted from the JWT payload) to ensure it remains valid before proxying the request.

## Prerequisites

- Python 3.6+
- A running Keycloak instance with a configured realm, client, and users.
- An upstream service to proxy requests to.
- Docker (optional, for containerized deployment).

## Environment Variables

The proxy relies on the following environment variables for configuration:

| Variable                 | Description                                                                | Required | Default Value       |
|--------------------------|----------------------------------------------------------------------------|----------|---------------------|
| `KEYCLOAK_BASE_URL`      | Base URL of the Keycloak server (e.g., `https://keycloak.mydomain.com`).   | Yes      | N/A                 |
| `KEYCLOAK_REALM`         | Keycloak realm name.                                                       | Yes      | N/A                 |
| `KEYCLOAK_CLIENT_ID`     | Keycloak client ID for authentication.                                     | Yes      | N/A                 |
| `KEYCLOAK_CLIENT_SECRET` | Keycloak client secret for authentication.                                 | Yes      | N/A                 |
| `PROXY_UPSTREAM_URL`     | URL of the upstream service to forward authenticated requests to.          | Yes      | N/A                 |
| `PROXY_AUTH_COOKIE_NAME` | Name of the cookie storing the access token.                               | Yes      | N/A                 |
| `PROXY_TOKEN_USERNAME`   | Username indicating the password is a token for introspection.             | No       | `__token__`         |

## How to Use

### Running with Docker

1. **Build the Docker Image**:
   ```bash
   $ docker build -t keycloak-basic-auth-proxy:0.1.0 .
   ```

2. **Run the Docker Container**:
   Replace the placeholder values with your actual configuration:
   ```bash
   $ docker run -d \
       -p 8000:8000 \
       -e KEYCLOAK_BASE_URL=https://keycloak.mydomain.com \
       -e KEYCLOAK_REALM=<keycloak-realm> \
       -e KEYCLOAK_CLIENT_ID=<keycloak-client-id> \
       -e KEYCLOAK_CLIENT_SECRET=<keycloak-client-secret> \
       -e PROXY_UPSTREAM_URL=http://myservice.mydomain.com \
       -e PROXY_AUTH_COOKIE_NAME=myservice:auth_token \
       keycloak-basic-auth-proxy:0.1.0
   ```

   - The proxy will listen on port `8000` by default.
   - Ensure the upstream service (`PROXY_UPSTREAM_URL`) is accessible from the container.

3. **Using Docker Compose**:
   For a more complex setup (e.g., integrating with other services), refer to the example in [ `./examples/pypiserver/docker-compose.yaml`](./examples/pypiserver/docker-compose.yaml).

### Running Locally

1. **Install Dependencies**:
   The script uses only Python standard library modules, so no additional dependencies are required.

2. **Set Environment Variables**:
   Export the required variables in your shell:
   ```bash
   $ export KEYCLOAK_BASE_URL=https://keycloak.mydomain.com
   $ export KEYCLOAK_REALM=<keycloak-realm>
   $ export KEYCLOAK_CLIENT_ID=<keycloak-client-id>
   $ export KEYCLOAK_CLIENT_SECRET=<keycloak-client-secret>
   $ export PROXY_UPSTREAM_URL=http://myservice.mydomain.com
   $ export PROXY_AUTH_COOKIE_NAME=myservice:auth_token
   ```

3. **Run the Server**:
   Start the server using the built-in WSGI server (for testing):
   ```bash
   $ python proxy.py
   ```
   The server will start on `0.0.0.0:8000`. Note that this is a single-threaded server (`wsgiref`) and not suitable for production use.

### Production Deployment

For production, deploy the application behind a WSGI server like Gunicorn or uWSGI, and consider adding a reverse proxy (e.g., Nginx) for load balancing and SSL termination.

Example with Gunicorn:
```bash
$ pip install gunicorn
$ gunicorn --bind 0.0.0.0:8000 proxy:application
```

## Logging

The proxy uses Python's `logging` module with the `INFO` level by default. Logs include timestamps, levels, and messages (e.g., errors from Keycloak requests). Logs are output to the console.

## Security Notes

- The access token is stored in an `HttpOnly` cookie to prevent client-side access via JavaScript.
- Token expiration is validated on each request using the JWT `exp` claim.
- Ensure `KEYCLOAK_CLIENT_SECRET` is kept secure and not exposed in logs or version control.

## Limitations

- The built-in `wsgiref` server is single-threaded and intended for testing only.
- Only `GET` and `POST` methods are explicitly handled in the code; other methods are passed through but not specifically tested.
- Error handling assumes a `502 Bad Gateway` response for upstream failures, which may need customization.

## Contributing

Feel free to submit issues or pull requests to enhance functionality, improve security, or add documentation.

