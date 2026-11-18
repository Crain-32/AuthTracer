package dev.crain.authtracer.graph;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * What an Egress authenticates with (OAUTH-05, SRC-16, SRC-17), which decides whose authorities the called service's
 * checks evaluate (decision 0021).
 */
@Supports({Feature.CALL_CREDENTIALS, Feature.APPLICATION_GRAPH})
public enum Credentials {
    /**
     * The caller's own bearer token, forwarded: the called service checks the same caller.
     */
    RELAY,
    /**
     * A token from an OAuth2 client registration (client credentials, or a separately authorized client).
     */
    OAUTH2_CLIENT,
    /**
     * Fixed credentials the service sends, e.g. basic auth or a token in a default header.
     */
    STATIC,
    /**
     * Nothing AuthTracer can see adds credentials.
     */
    NONE,
    /**
     * Something sets credentials, but AuthTracer can't tell what.
     */
    UNKNOWN;

    /**
     * Whether the called service's checks constrain the original caller. Graphs scanned before credentials were
     * recorded ({@code null}) keep that assumption.
     */
    @Supports(Feature.EXPOSURES)
    public static boolean callerChecked(Credentials credentials) {
        return credentials == null || credentials == RELAY;
    }
}
