package dev.crain.authtracer.graph;

import java.util.Comparator;
import java.util.List;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * What one identity seen in traces was granted, and which of it the checks on its requests needed (decision 0023).
 * An identity is a set of granted authorities with an authentication type: traces carry no principal name. A test
 * identity should hold only what the paths it exercises require, so {@code unneeded} lists what it is over-scoped
 * with.
 *
 * @param authorities what it was granted, sorted; Spring Security's own {@code FACTOR_} authorities are left out
 * @param authenticationType e.g. {@code JwtAuthenticationToken}
 * @param requests the requests served for it, counting each service a request reaches
 * @param endpoints the endpoints those requests hit, as {@code service METHOD /route}
 * @param needed granted authorities that a check it passed asked for
 * @param unneeded granted authorities that no check it passed asked for
 * @param denied checks that denied it
 * @param unread checks it passed whose requirement AuthTracer can't read, which might need any authority
 */
@Supports({Feature.IDENTITIES, Feature.SYSTEM_GRAPH})
public record IdentityUsage(List<String> authorities, String authenticationType, long requests,
        List<String> endpoints, List<String> needed, List<String> unneeded, long denied, long unread) {

    static final Comparator<IdentityUsage> ORDER = Comparator.comparing(IdentityUsage::authenticationType)
            .thenComparing(usage -> String.join(",", usage.authorities()));

    public IdentityUsage {
        authorities = List.copyOf(authorities);
        endpoints = List.copyOf(endpoints);
        needed = List.copyOf(needed);
        unneeded = List.copyOf(unneeded);
    }
}
