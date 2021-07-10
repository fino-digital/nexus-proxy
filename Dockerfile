# -- build
FROM gradle:jdk8 AS builder
COPY ./ /src/
WORKDIR /src/
RUN gradle --debug --no-daemon shadowJar

# -- run
FROM gcr.io/distroless/java:8

ENV BIND_HOST="0.0.0.0" \
    BIND_PORT="8080" \
    CLIENT_ID="REPLACE_ME" \
    CLIENT_SECRET="REPLACE_ME" \
    CLOUD_IAM_AUTH_ENABLED="true" \
    NEXUS_HTTP_HOST="nexus.example.com" \
    REPOSITORY_PATH="/repository/*" \
    REDIRECT_URL="<oauth-callback>" \
    SESSION_TTL="1440000" \
    UPSTREAM_HOST="localhost" \
    UPSTREAM_HTTP_PORT="8081" \
    JWK_URL="<openid-certs>" \
    TOKEN_ENDPOINT="<openid-token-endpoint>" \
    AUTHORIZE_ENDPOINT="<openid-authorize-url>" \
    REQUEST_SCOPES="" \
    USER_ID_CLAIM="email" \
    HMAC_SHA256_SECRET="" \
    PASSTHRU_AUTH_HEADER="true"

COPY --from=builder /src/build/libs/nexus-proxy-2.3.0.jar /nexus-proxy.jar

EXPOSE 8080 8443

CMD ["/nexus-proxy.jar"]