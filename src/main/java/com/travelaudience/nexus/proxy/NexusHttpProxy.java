package com.travelaudience.nexus.proxy;

import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.RoutingContext;

/**
 * A basic class which proxies user requests to a Nexus instance, conveying authentication information.
 *
 * @see <a href="https://books.sonatype.com/nexus-book/reference3/security.html#remote-user-token">Authentication via Remote User Token</a>
 */
public final class NexusHttpProxy {
    private static final CharSequence X_FORWARDED_PROTO = HttpHeaders.createOptimized("X-Forwarded-Proto");
    private static final CharSequence X_FORWARDED_FOR = HttpHeaders.createOptimized("X-Forwarded-For");

    private final String host;
    private final HttpClient httpClient;
    private final String nexusRutHeader;
    private final int port;
    private final boolean passThruAuthHeader;

    private NexusHttpProxy(final Vertx vertx,
                           final String host,
                           final int port,
                           final boolean passThruAuthHeader) {
        this.host = host;
        this.httpClient = vertx.createHttpClient();
        this.nexusRutHeader = "X-Auth-Username";
        this.port = port;
        this.passThruAuthHeader = passThruAuthHeader;
    }

    /**
     * Creates a new instance of {@link NexusHttpProxy}.
     *
     * @param vertx          the base {@link Vertx} instance.
     * @param host           the host we will be proxying to.
     * @param port           the port we will be proxying to.
     * @return a new instance of {@link NexusHttpProxy}.
     */
    public static final NexusHttpProxy create(final Vertx vertx,
                                              final String host,
                                              final int port,
                                              final boolean passThruAuthHeader) {
        return new NexusHttpProxy(vertx, host, port, passThruAuthHeader);
    }

    /**
     * Proxies the specified HTTP request, enriching its headers with authentication information.
     *
     * @param userId  the ID of the user making the request.
     * @param accessToken the validated JWT token
     * @param origReq the original request (i.e., {@link RoutingContext#request()}.
     * @param origRes the original response (i.e., {@link RoutingContext#request()}.
     */
    public void proxyUserRequest(final String userId,
                                 final String accessToken,
                                 final HttpServerRequest origReq,
                                 final HttpServerResponse origRes) {
        final Handler<HttpClientResponse> proxiedResHandler = proxiedRes -> {
            origRes.setChunked(true);
            origRes.setStatusCode(proxiedRes.statusCode());
            origRes.headers().setAll(proxiedRes.headers());
            origRes.headers().remove(HttpHeaders.CONTENT_LENGTH);
            proxiedRes.handler(origRes::write);
            proxiedRes.endHandler(v -> origRes.end());
        };

        final HttpClientRequest proxiedReq;
        proxiedReq = httpClient.request(origReq.method(), port, host, origReq.uri(), proxiedResHandler);
        if(origReq.method() == HttpMethod.OTHER) {
            proxiedReq.setRawMethod(origReq.rawMethod());
        }
        proxiedReq.setChunked(true);
        proxiedReq.headers().add(X_FORWARDED_PROTO, getHeader(origReq, X_FORWARDED_PROTO, origReq.scheme()));
        proxiedReq.headers().add(X_FORWARDED_FOR, getHeader(origReq, X_FORWARDED_FOR, origReq.remoteAddress().host()));
        proxiedReq.headers().addAll(origReq.headers());
        
        // Don't pass auth header to upstream if there's a valid JWT
        if (!passThruAuthHeader || accessToken != null) {
            proxiedReq.headers().remove(HttpHeaders.AUTHORIZATION);
        }
        
        // Always include valid JWT in header
        if (accessToken != null) {
            proxiedReq.headers().add("X-Auth-Token", accessToken);
        }

        proxiedReq.headers().remove(HttpHeaders.CONTENT_LENGTH);
        injectRutHeader(proxiedReq, userId);
        origReq.handler(proxiedReq::write);
        origReq.endHandler(v -> proxiedReq.end());
    }

    private final void injectRutHeader(final HttpClientRequest req,
                                       final String userId) {
        if (nexusRutHeader != null && nexusRutHeader.length() > 0 && userId != null && userId.length() > 0) {
            req.headers().add(nexusRutHeader, userId);
        }
    }

    private static final String getHeader(final HttpServerRequest req,
                                          final CharSequence name,
                                          final String defaultValue) {
        final String originalHeader = req.headers().get(name);

        if (originalHeader == null) {
            return defaultValue;
        } else {
            return originalHeader;
        }
    }
}
