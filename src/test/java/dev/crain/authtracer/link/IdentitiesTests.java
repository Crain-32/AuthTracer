package dev.crain.authtracer.link;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import dev.crain.authtracer.graph.Requirement;
import org.junit.jupiter.api.Test;

class IdentitiesTests {

    @Test
    void callersWithoutAnIdentityAreNotIdentities() {
        Identities identities = new Identities();
        // A health check: no Authentication at all, so Spring tags n/a.
        assertThat(identities.request(List.of(decision("n/a", "n/a")), "service GET /actuator/health")).isEmpty();
        assertThat(identities.request(List.of(decision("AnonymousAuthenticationToken", "[ROLE_ANONYMOUS]")),
                "service GET /public")).isEmpty();
        assertThat(identities.request(List.of(decision("JwtAuthenticationToken", "[SCOPE_read]")),
                "service GET /items")).isPresent();
        assertThat(identities.usages()).singleElement()
                .satisfies(usage -> assertThat(usage.authorities()).containsExactly("SCOPE_read"));
    }

    @Test
    void whatACheckNeededIsWhatItAskedForThatTheIdentityHolds() {
        Identities identities = new Identities();
        Identities.Identity identity = identities.request(List.of(decision("JwtAuthenticationToken",
                "[SCOPE_items.read, SCOPE_items.write, ROLE_ADMIN, SCOPE_audit]")), "service GET /items").orElseThrow();

        // Spring names the authorities an authority check asked for.
        identity.check(true, "AuthorityAuthorizationDecision [granted=true, authorities=[SCOPE_items.read]]",
                Optional.empty());
        // An expression's are read from the Location it matched, through its operands.
        identity.check(true, "ExpressionAuthorizationDecision [granted=true, expressionAttribute=hasRole('ADMIN') and"
                + " hasAuthority('SCOPE_audit')]", Optional.of(Requirement.and(List.of(Requirement.anyAuthority(
                        List.of("ROLE_ADMIN")), Requirement.anyAuthority(List.of("SCOPE_audit"))))));
        // These ask for nothing, or a sign-in only.
        identity.check(true, "AuthorizationDecision [granted=true]", Optional.of(Requirement.permitAll()));
        identity.check(true, "AuthorizationDecision [granted=true]", Optional.of(Requirement.fullyAuthenticated()));
        identity.check(true, "AuthorizationDecision [granted=true]", Optional.of(Requirement.rememberMe()));

        assertThat(identities.usages()).singleElement().satisfies(usage -> {
            assertThat(usage.needed()).containsExactly("ROLE_ADMIN", "SCOPE_audit", "SCOPE_items.read");
            assertThat(usage.unneeded()).containsExactly("SCOPE_items.write");
            assertThat(usage.unread()).isZero();
        });
    }

    private static TraceSpan decision(String type, String authorities) {
        return new TraceSpan("t", "s", null, null, "authorization", "service", 0, Map.of(
                "spring.security.authentication.type", type, "spring.security.authentication.authorities",
                authorities));
    }
}
