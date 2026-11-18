package dev.crain.authtracer.graph;

import java.util.SortedSet;
import java.util.TreeSet;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * The OAuth2 client registration an Egress's own token is issued to (decision 0075 amended), as the service's
 * {@code spring.security.oauth2.client.registration.<id>} and its provider's properties declare it.
 *
 * @param id the registration's id
 * @param clientId the client it authenticates as at the authorization server; {@code null} when not known
 * @param grantType its {@code authorization-grant-type}; {@code null} when not set
 * @param scopes the scopes it asks for
 * @param tokenUri its provider's token endpoint, when it names one
 * @param issuerUri its provider's issuer, whose OpenID configuration names the token endpoint, when it names one
 */
@Supports({Feature.CALL_CREDENTIALS, Feature.FINDING_TOKEN_REJECTED, Feature.APPLICATION_GRAPH})
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record Registration(String id, String clientId, String grantType, SortedSet<String> scopes, String tokenUri,
        String issuerUri) {

    public Registration {
        scopes = scopes == null ? new TreeSet<>() : new TreeSet<>(scopes);
    }
}
