package com.travelaudience.nexus.proxy;

import static com.travelaudience.nexus.proxy.ContextKeys.PROXY;
import static com.travelaudience.nexus.proxy.Paths.ALL_PATHS;

import com.google.common.primitives.Ints;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.http.HttpHeaders;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.VirtualHostHandler;
import io.vertx.ext.web.templ.HandlebarsTemplateEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;

public abstract class BaseNexusProxyVerticle extends AbstractVerticle {
    private static final Logger LOGGER = LoggerFactory.getLogger(BaseNexusProxyVerticle.class);

    private static final String BIND_HOST = System.getenv("BIND_HOST");
    private static final Integer BIND_PORT = Ints.tryParse(System.getenv("BIND_PORT"));
    private static final Boolean ENFORCE_HTTPS = Boolean.parseBoolean(System.getenv("ENFORCE_HTTPS"));
    private static final String UPSTREAM_HOST = System.getenv("UPSTREAM_HOST");
    private static final Integer UPSTREAM_HTTP_PORT = Ints.tryParse(System.getenv("UPSTREAM_HTTP_PORT"));
    public static final Boolean PASSTHRU_AUTH_HEADER = Boolean.parseBoolean(System.getenv("PASSTHRU_AUTH_HEADER"));
    private static final CharSequence X_FORWARDED_PROTO = HttpHeaders.createOptimized("X-Forwarded-Proto");
    protected final String nexusHttpHost = System.getenv("NEXUS_HTTP_HOST");

    protected final HandlebarsTemplateEngine handlebars = HandlebarsTemplateEngine.create();

    @Override
    public final void start() throws Exception {
        final NexusHttpProxy httpProxy = NexusHttpProxy.create(
                vertx,
                UPSTREAM_HOST,
                UPSTREAM_HTTP_PORT,
                PASSTHRU_AUTH_HEADER);
        final Router router = Router.router(
                vertx
        );

        preconfigureRouting(router);

        router.route(ALL_PATHS).handler(VirtualHostHandler.create(nexusHttpHost, ctx -> {
            ctx.data().put(PROXY, httpProxy);
            ctx.next();
        }));

        router.route(ALL_PATHS).handler(VirtualHostHandler.create(nexusHttpHost, ctx -> {
            final String protocol = ctx.request().headers().get(X_FORWARDED_PROTO);

            if (!ENFORCE_HTTPS || "https".equals(protocol)) {
                ctx.next();
                return;
            }

            final URI oldUri;

            try {
                oldUri = new URI(ctx.request().absoluteURI());
            } catch (final URISyntaxException ex) {
                throw new RuntimeException(ex);
            }

            if ("https".equals(oldUri.getScheme())) {
                ctx.next();
                return;
            }
            
            ctx.put("nexus_http_host", nexusHttpHost);

            handlebars.render(ctx, "templates", "/http-disabled.hbs", res -> { // The '/' is somehow necessary.
                if (res.succeeded()) {
                    ctx.response().setStatusCode(400).end(res.result());
                } else {
                    ctx.response().setStatusCode(500).end("Internal Server Error");
                }
            });
        }));

        configureRouting(router);

        router.route(ALL_PATHS).handler(ctx -> {
        	String expectHeader = ctx.request().getHeader("Expect");
            if (expectHeader != null && 
            		expectHeader.contains("100-continue")) {
            	ctx.response().writeContinue();
            }

            final NexusHttpProxy proxy = ((NexusHttpProxy) ctx.data().get(PROXY));

            if (proxy != null) {
                proxy.proxyUserRequest(getUserId(ctx), getAccessToken(ctx), ctx.request(), ctx.response());
                return;
            }

            // The only way proxy can be null is if the Host header of the request doesn't match any of the known
            // hosts (NEXUS_DOCKER_HOST or NEXUS_HTTP_HOST). In that scenario we should fail gracefully and indicate
            // how to access Nexus properly.
            ctx.put("nexus_http_host", nexusHttpHost);
            handlebars.render(ctx, "templates", "/invalid-host.hbs", res -> { // The '/' is somehow necessary.
                if (res.succeeded()) {
                    ctx.response().setStatusCode(400).end(res.result());
                } else {
                    ctx.response().setStatusCode(500).end("Internal Server Error");
                }
            });
        });

        vertx.createHttpServer().requestHandler(
                router::accept
        ).listen(BIND_PORT, BIND_HOST, res -> {
            if (res.succeeded()) {
                LOGGER.info("Listening at {}:{}.", BIND_HOST, BIND_PORT);
            } else {
                LOGGER.error("Couldn't bind to {}:{}.", BIND_HOST, BIND_PORT, res.cause());
            }
        });
    }

    /**
     * Configures the main routes. This will be called after {@link BaseNexusProxyVerticle#preconfigureRouting(Router)},
     * after user-agent checking on root and after the setup of virtual hosts handlers, but before the actual proxying.
     * @param router the {@link Router} which to configure.
     */
    protected abstract void configureRouting(final Router router);

    /**
     * Returns the currently authenticated user, or {@code null} if no valid authentication info is present.
     * @param ctx the current routing context.
     * @return the currently authenticated user, or {@code null} if no valid authentication info is present.
     */
    protected abstract String getUserId(final RoutingContext ctx);

    protected abstract String getAccessToken(final RoutingContext ctx);

    /**
     * Configures prerouting routes. This will be called right after the creation of {@code router}.
     * @param router the {@link Router} which to configure.
     */
    protected abstract void preconfigureRouting(final Router router);
}
