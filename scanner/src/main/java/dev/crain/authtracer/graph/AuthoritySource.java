package dev.crain.authtracer.graph;

import java.util.List;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeSet;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * Where the authorities behind a service's checks come from, and therefore how fresh they are.
 *
 * @param roleHierarchy each role's directly implied roles, from a {@code RoleHierarchy} bean; role checks in the
 *        graph already include the roles that imply them
 * @param granted the only authorities a request can carry, when the scan can tell: exact names, or a prefix and
 *        {@code *} for any authority it starts ({@code SCOPE_*}); {@code null} when any authority may be granted (a
 *        user store, a custom converter, a mechanism whose authorities the scan doesn't read)
 * @param jwt what a resource server reads from the JWTs it accepts
 */
@Supports({Feature.AUTHORITY_SOURCE, Feature.APPLICATION_GRAPH})
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthoritySource(Kind kind, Freshness freshness, String detail,
        SortedMap<String, SortedSet<String>> roleHierarchy, SortedSet<String> granted, Jwt jwt) {

    public static final AuthoritySource UNKNOWN = new AuthoritySource(Kind.UNKNOWN, Freshness.UNKNOWN, null);

    public AuthoritySource(Kind kind, Freshness freshness, String detail) {
        this(kind, freshness, detail, null, null, null);
    }

    public AuthoritySource(Kind kind, Freshness freshness, String detail,
            SortedMap<String, SortedSet<String>> roleHierarchy) {
        this(kind, freshness, detail, roleHierarchy, null, null);
    }

    public AuthoritySource withRoleHierarchy(SortedMap<String, SortedSet<String>> roleHierarchy) {
        return new AuthoritySource(kind, freshness, detail, roleHierarchy.isEmpty() ? null : roleHierarchy, granted,
                jwt);
    }

    /**
     * Whether a request may carry the authority: always, unless the scan knows every authority the service grants.
     */
    public boolean mayGrant(String authority) {
        return granted == null || granted.stream().anyMatch(pattern -> pattern.endsWith("*")
                ? authority.startsWith(pattern.substring(0, pattern.length() - 1)) : pattern.equals(authority));
    }

    /**
     * The same source, granting only these authorities.
     */
    @Supports({Feature.FINDING_ALWAYS_DENIED, Feature.FINDING_TOKEN_REJECTED})
    public AuthoritySource withGranted(SortedSet<String> granted) {
        return new AuthoritySource(kind, freshness, detail, roleHierarchy, granted, jwt);
    }

    /**
     * The authorities that keep a requirement from ever passing (any of {@code hasAnyAuthority}, all of
     * {@code hasAllAuthorities}, through {@code and}/{@code or}), empty when a request may meet it.
     */
    @Supports({Feature.FINDING_ALWAYS_DENIED, Feature.FINDING_TOKEN_REJECTED})
    public SortedSet<String> unmet(Requirement requirement) {
        SortedSet<String> missing = new TreeSet<>();
        switch (requirement.kind()) {
            case ANY_AUTHORITY -> {
                if (requirement.authorities().stream().noneMatch(this::mayGrant)) {
                    missing.addAll(requirement.authorities());
                }
            }
            case ALL_AUTHORITIES -> requirement.authorities().stream().filter(authority -> !mayGrant(authority))
                    .forEach(missing::add);
            case AND -> requirement.operands().stream().map(this::unmet).filter(found -> !found.isEmpty())
                    .findFirst().ifPresent(missing::addAll);
            case OR -> {
                List<SortedSet<String>> each = requirement.operands().stream().map(this::unmet).toList();
                if (!each.isEmpty() && each.stream().noneMatch(SortedSet::isEmpty)) {
                    each.forEach(missing::addAll);
                }
            }
            default -> {
            }
        }
        return missing;
    }

    public enum Kind {
        JWT_CLAIMS, OPAQUE_TOKEN_INTROSPECTION, USER_DETAILS,
        /** An external identity provider at login (OAuth2 Login, SAML 2.0 Login), kept in the session. */
        IDENTITY_PROVIDER,
        /** Application code in a filter that sets the Authentication itself (decision 0071). */
        CUSTOM_FILTER, UNKNOWN
    }

    public enum Freshness {
        /** Fixed when the token was issued or the user logged in. */
        SNAPSHOT,
        /** Re-read on every request. */
        LIVE,
        UNKNOWN
    }

    /**
     * What a resource server reads from the JWTs it accepts (SRC-02, SRC-03, OAUTH-06).
     *
     * @param authorities the claims whose values become authorities, each with the prefix the values get
     * @param audiences the audiences it accepts (a token must name one); empty when it doesn't check them
     * @param validators the checks a token must pass beyond the default expiry check
     * @param unread the validators and claim converters the scan can't read: what they accept or rewrite is unknown
     * @param rewritten the claims a {@code MappedJwtClaimSetConverter} rewrites before authorities are read
     */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public record Jwt(List<ClaimAuthorities> authorities, SortedSet<String> audiences, SortedSet<String> validators,
            SortedSet<String> unread, SortedSet<String> rewritten) {

        public Jwt {
            authorities = authorities == null ? List.of() : List.copyOf(authorities);
            audiences = sorted(audiences);
            validators = sorted(validators);
            unread = sorted(unread);
            rewritten = sorted(rewritten);
        }

        private static SortedSet<String> sorted(SortedSet<String> values) {
            return values == null ? new TreeSet<>() : new TreeSet<>(values);
        }

        /**
         * Whether every token the service accepts names one of the audiences.
         */
        @Supports(Feature.FINDING_TOKEN_REJECTED)
        public boolean checksAudience() {
            return !audiences.isEmpty();
        }
    }

    /**
     * A claim's values as authorities: {@code JwtGrantedAuthoritiesConverter}'s, or an
     * {@code ExpressionJwtGrantedAuthoritiesConverter}'s.
     *
     * @param claims the claims read, the first the token has ({@code scope}, then {@code scp}, by default); empty
     *        when an expression selects the values, or the scan can't read the name
     * @param expression the SpEL expression that selects the values
     * @param prefix the prefix each value gets
     * @param delimiter what a claim held as one string is split on, when it isn't a space
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ClaimAuthorities(List<String> claims, String expression, String prefix, String delimiter) {

        public ClaimAuthorities {
            claims = claims == null ? List.of() : List.copyOf(claims);
        }
    }
}
