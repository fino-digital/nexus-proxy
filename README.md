# nexus-proxy

_This project is a fork of the original [nexus-proxy (by travelaudience)](https://github.com/travelaudience/nexus-proxy) which allowed optional authentication 
against the Google Cloud IAM. It is not hard-wired to Google Cloud IAM anymore. You can use it with any IDP which supports the OAuth2 Code Authorization Flow.
Furthermore the docker proxy was removed since we only needed authentication for npm and gradle/maven._

A proxy for Nexus Repository Manager that allows for optional authentication against an external identity provider (which implements OAuth2/OpenID).

## Pre-requisites

For building the project:

* JDK 8.

For basic proxying:

* A domain name configured with an `A` and a `CNAME` records pointing to the proxy.
  * For local testing one may create two entries on `/etc/hosts` pointing to `127.0.0.1`.
* A running and properly configured instance of Nexus.
  * One may use the default `8081` port for the HTTP connector.

For opt-in authentication against an IDP:

* All of the above.
* A properly configured IDP, e.g. Keycloak
* A set of credentials (`CLIENT_ID` & `CLIENT_SECRET`)
* OAuth2 Endpoint URLs (`AUTHORIZE_ENDPOINT`, `TOKEN_ENDPOINT`, `JWK_URL`)
* Scopes and claim, specify the user ID claim, defaults to email (`USER_ID_CLAIM`)
* Proper configuration of the resulting client's `REDIRECT_URL`.

## Running the proxy

## Running the proxy with OpenID Authentication

The following command will run the proxy on port `8080` with 
authentication against an OpenID IDP enabled and pointing to a local Nexus instance:

```bash
$ BIND_PORT="8080" \
  CLOUD_IAM_AUTH_ENABLED="true" \
  CLIENT_ID="my-client-id" \
  CLIENT_SECRET="my-client-secret" \
  NEXUS_HTTP_HOST="nexus.example.com" \
  REPOSITORY_PATH="/repository/*" \
  REDIRECT_URL="https://nexus.example.com/oauth/callback" \
  SESSION_TTL="1440000" \
  UPSTREAM_HTTP_PORT="8081" \
  UPSTREAM_HOST="localhost" \
  TOKEN_ENDPOINT="https://<sso-base-url>/openid-connect/token" \
  JWK_URL="https://<sso-base-url>/openid-connect/certs" \
  TOKEN_ENDPOINT="https://<sso-base-url>/openid-connect/auth" \
  REQUEST_SCOPES="" \
  USER_ID_CLAIM="email" \
  HMAC_SHA256_SECRET="" \
  PASSTHRU_AUTH_HEADER="true"
  java -jar ./build/libs/nexus-proxy-2.3.0.jar
```

## Environment Variables

| Name                                | Description |
|-------------------------------------|-------------|
| `BIND_HOST`                         | The interface on which to listen for incoming requests. Defaults to `0.0.0.0`. |
| `BIND_PORT`                         | The port on which to listen for incoming requests. |
| `CLIENT_ID`                         | The application's OAuth2 client ID|
| `CLIENT_SECRET`                     | The abovementioned application's client secret. |
| `CLOUD_IAM_AUTH_ENABLED`            | Whether to enable authentication against an IDP. |
| `LOG_LEVEL`                         | The desired log level (i.e., `trace`, `debug`, `info`, `warn` or `error`). Defaults to `info`. |
| `NEXUS_HTTP_HOST`                   | The host used to access the Nexus UI and Maven repositories. |
| `REPOSITORY_PATH`                   | Repository route serving data to CLI utilities like maven/nuget with http header authentication, defaults to /repository/* |
| `REDIRECT_URL`                      | The URL where to redirect users after the OAuth2 consent screen. |
| `SESSION_TTL`                       | The TTL (in _milliseconds_) of a user's session. |
| `UPSTREAM_HTTP_PORT`                | The port where the proxied Nexus instance listens. |
| `UPSTREAM_HOST`                     | The host where the proxied Nexus instance listens. |
| `AUTHORIZE_ENDPOINT`                | The OAuth2/OpenID auth endpoint for the Authorize Flow |
| `TOKEN_ENDPOINT`                    | The OAuth2/OpenID token endpoint for the Authorize Flow |
| `JWK_URL`                           | URL where the server can receive the IDP's JWK. Needed for verifying the tokens signature.  |
| `REQUEST_SCOPES`                    | Request any additional scopes. The openid scope is always requested |
| `USER_ID_CLAIM`                     | What claim to use as the user id |
| `HMAC_SHA256_SECRET`                | String secret used to encrypt JWT tokens created for CLI tools. Leave blank to auto-generate, but they will not survive a restart. |
| `PASSTHRU_AUTH_HEADER`              | Specify true to pass Authorization header upstream if user name is not 'apikey' if basic auth header is passed in. Defaults to true. |