package dev.crain.authtracer.scan.spring;

import java.net.URI;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Egress;

/**
 * An absolute URL a service is configured with (an issuer, a config server, a SOAP endpoint), split as an Egress has
 * it: the base URL ({@code http://idp:9000}) and the path.
 *
 * @param path the raw path, empty for none
 */
@Supports({Feature.INFRASTRUCTURE_CALLS, Feature.SERVICE_CALLS})
record AbsoluteUrl(String base, String path) {

    /**
     * Empty when the text isn't a URL with a scheme and a host, e.g. one with an unresolved placeholder.
     */
    static Optional<AbsoluteUrl> parse(String url) {
        try {
            URI uri = URI.create(url.trim());
            // A host name with an underscore (config_server) is no host to URI, but its authority still names it.
            String host = uri.getHost() != null ? uri.getHost() : uri.getRawAuthority() == null ? null
                    : uri.getRawAuthority().replaceFirst("^.*@", "").replaceFirst(":\\d+$", "");
            if (uri.getScheme() == null || host == null || host.isEmpty()) {
                return Optional.empty();
            }
            int port = uri.getHost() != null ? uri.getPort() : uri.getRawAuthority().matches(".*:\\d+$")
                    ? Integer.parseInt(uri.getRawAuthority().replaceFirst("^.*:", "")) : -1;
            String base = uri.getScheme() + "://" + host + (port > 0 ? ":" + port : "");
            // Only an opaque URI (mailto:..) has no path, and it has no host either.
            return Optional.of(new AbsoluteUrl(base, uri.getRawPath()));
        }
        catch (IllegalArgumentException notUrl) {
            return Optional.empty();
        }
    }

    /**
     * A call to a path there, with no credentials AuthTracer can see.
     */
    Egress call(String client, String method, String route, CodeRef site) {
        return Egress.of(client, method, route, base, null, site, null).withCredentials(Credentials.NONE, null);
    }
}
